import argparse
import os
import sys
import logging
from configparser import ConfigParser
from dataclasses import dataclass
from multiprocessing.pool import ThreadPool

from ws_copy_policy._version import __version__, __tool_name__
import requests
import json
from copy import deepcopy

LOG_DIR = 'logs'
LOG_FILE_WITH_PATH = LOG_DIR + '/ws-copy-policy.log'
PROJECT = 'project'
PRODUCT = 'product'
logger = logging.getLogger()
conf = None

agent_info = "agentInfo"
PS = "ps-"
AGENT_NAME = "copy-policy"
AGENT_VERSION = "0.1.2"

agent_info_details = {"agent": PS + AGENT_NAME, "agentVersion": AGENT_VERSION}


def parse_config():
    @dataclass
    class Config:
        url: str
        org_token: str
        user_key: str
        scope: str
        thread: int

    global conf

    if len(sys.argv) < 3:
        maybe_config_file = True
    if len(sys.argv) == 1:
        conf_file = "../config/params.config"
    elif not sys.argv[1].startswith('-'):
        conf_file = sys.argv[1]
    else:
        maybe_config_file = False

    if maybe_config_file:                             # Covers no conf file or only conf file
        if os.path.exists(conf_file):
            logger.info(f"loading configuration from file: {conf_file}")
            config = ConfigParser()
            config.optionxform = str
            if os.path.exists(conf_file):
                logger.info(f"loading configuration from file: {conf_file}")
                config.read(conf_file)

                conf = Config(
                    url=config['DEFAULT'].get("wsUrl"),
                    org_token=config['DEFAULT'].get("orgToken"),
                    user_key=config['DEFAULT'].get("userKey"),
                    scope=config['DEFAULT'].get("scope"),
                    thread=config['DEFAULT'].getint('thread', 5))
        else:
            logger.error(f"No configuration file found at: {conf_file}")
            raise FileNotFoundError
    else:
        parser = argparse.ArgumentParser(description="Arguments parser")
        parser.add_argument("-u", "--url", help="WS url", dest='url', required=False)
        parser.add_argument("-k", "--userKey", help="WS User Key", dest='user_key', required=False)
        parser.add_argument("-o", "--orgToken", help="WS Org Token", dest='org_token', required=False)
        parser.add_argument("-s", "--scope", help="WS scope", dest='scope', required=False)
        parser.add_argument("-t", "--thread", help="thread number", dest='thread', required=False, type=int, default=5)
        conf = parser.parse_args()

    return conf


def main():
    global conf
    try:
        conf = parse_config()
    except FileNotFoundError:
        exit(-1)

    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info("starting...")
    logging.info("validating parameters")

    if conf.scope != PROJECT and conf.scope != PRODUCT:
        logging.error("scope should be 'project' or 'product'. Please check input parameters and try again.")
        exit(1)
    logging.info("using url %s", conf.url)
    get_policies(conf.org_token, conf.user_key, conf.url, conf.scope, conf.thread)

    logging.info("Status: SUCCESS")
    sys.exit(0)


def get_policies(org_token, user_key, url, scope, thread):
    """

    :rtype: object
    """
    # getOrganizationProjectTags api
    if scope == PROJECT:
        request_type = "getOrganizationProjectTags"
    elif scope == PRODUCT:
        request_type = "getOrganizationProductTags"
    body = {"requestType": request_type,
            "userKey": user_key,
            "orgToken": org_token}
    scope_tags = post_request(body, url)
    template_value_to_policies = {}
    scope_token_to_template_value_and_policies = {}
    fill_template_values_and_projects_from_response(scope_tags, template_value_to_policies,
                                                    scope_token_to_template_value_and_policies,
                                                    scope, user_key, thread, url)

    scope_size = len(scope_token_to_template_value_and_policies)
    logging.info(f"TOTAL: {scope_size} {scope}s have a destination tag value and should be handled")
    size_of_finished_copies = 1
    for token in scope_token_to_template_value_and_policies:
        template_value = scope_token_to_template_value_and_policies[token]["template"]
        if scope == PROJECT:
            scope_name = scope_token_to_template_value_and_policies[token]["project_name"]
        elif scope == PRODUCT:
            scope_name = scope_token_to_template_value_and_policies[token]["product_name"]
        if (template_value in template_value_to_policies):
            template_policies = template_value_to_policies[template_value]
            target_policies = scope_token_to_template_value_and_policies[token]["policies"]
            # change policies from the target only if there are differences between template
            # policies and target policies
            copy_template_policies = deepcopy(template_policies)
            copy_target_policies = deepcopy(target_policies)
            if not is_template_policies_and_target_policies_equals(copy_template_policies, copy_target_policies):
                logging.info(f"handling {size_of_finished_copies} out of the {scope_size} {scope}s.")
                delete_policies_from_scope(token, scope_name, target_policies, url, scope, user_key)
                add_policies_from_template_to_target(token, scope_name, template_policies, url, scope, user_key)
            else:
                logging.info(f"handling {size_of_finished_copies} out of the {scope_size} {scope}s: "
                             f"{scope} {scope_name} has a destination value {template_value}, but it "
                             f"already contains the policies like in source {scope_name}. Skip to the next {scope}.")
        else:
            logging.warning(f"handling {size_of_finished_copies} out of the {scope_size} {scope}s: "
                            f"{scope} {scope_name} has a destination key value {template_value}, "
                            f"but there is no {scope} with this source key value. Skip to the next {scope}.")
        size_of_finished_copies = size_of_finished_copies + 1
        #logging.info(f"finish handling {size_of_finished_copies} out of the {scope_size} {scope}s")


def post_request(body, url) -> object:

    headers = {'content-type': 'application/json'}
    body.update({agent_info: agent_info_details})
    response = requests.post(url, data=json.dumps(body), headers=headers)
    response_object = json.loads(response.text)
    check_errors_in_response(response_object)
    return response_object


def check_errors_in_response(response):
    """

    :rtype: object
    """
    error = False
    if "errorCode" in response:
        logging.error(f"Error code: {response['errorCode']}")
        error = True
    if "errorMessage" in response:
        logging.error(f"Error message: {response['errorMessage']}")
        error = True
    if error:
        logging.error("Status: FAILURE")
        sys.exit(1)


def fill_template_values_and_projects_from_response(response, template_value_to_policies,
                                                    scope_token_to_template_value_and_policies,
                                                    scope, user_key, thread, url):
    """

    :rtype: object
    """
    tag_template_key = "Policy.Template.Source"
    tag_scope_set_policies_key = "Policy.Template.Destination"
    if scope == PROJECT:
        scope_array = response["projectTags"]
        request_type = "getProjectPolicies"
    if scope == PRODUCT:
        scope_array = response["productTags"]
        request_type = "getProductPolicies"
    body = {"requestType": request_type,
            "userKey": user_key}
    if scope_array and len(scope_array) > 0:
        with ThreadPool(processes=thread) as thread_pool:
            thread_pool.starmap(worker, [(scope_item, body, request_type, tag_template_key, template_value_to_policies,
                                          tag_scope_set_policies_key, scope_token_to_template_value_and_policies,
                                          scope, url) for scope_item in scope_array])


def worker(scope_item, body, request_type, tag_template_key, template_value_to_policies,
           tag_scope_set_policies_key, scope_token_to_template_value_and_policies, scope, url):
    """

    :rtype: object
    """
    tags = scope_item["tags"]
    scope_token = scope_item["token"]
    if scope == PROJECT:
        body["projectToken"] = scope_token
    if scope == PRODUCT:
        body["productToken"] = scope_token
        logging.info(f"Start {request_type} api", )
    headers = {'content-type': 'application/json'}
    response = requests.post(url, data=json.dumps(body), headers=headers)
    scope_policies = json.loads(response.text)
    check_errors_in_response(scope_policies)
    #scope_policies = post_request(request_type, body)
    if tag_template_key in tags:
        logging.info(f"found source {scope}: {scope_item['name']}. Key value: {tags[tag_template_key]}")
        # getProjectPolicies api
        template_value_to_policies[tags[tag_template_key]] = scope_policies["policies"]
    elif tag_scope_set_policies_key in tags:
        logging.info(f"found destination {scope}: {scope_item['name']}. Key value: {tags[tag_scope_set_policies_key]}")
        scope_policies["template"] = tags[tag_scope_set_policies_key]
        if scope == PROJECT:
            scope_policies["project_name"] = scope_item["name"]
        if scope == PRODUCT:
            scope_policies["product_name"] = scope_item["name"]
        scope_token_to_template_value_and_policies[scope_token] = scope_policies


def ordered(obj):
    """

    :param obj:
    :return:
    """
    if isinstance(obj, dict):
        return sorted((k, ordered(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return sorted(ordered(x) for x in obj)
    else:
        return obj


def is_template_policies_and_target_policies_equals(template_policies, target_policies):
    """

    :rtype: object
    """
    equals_policies = False
    if len(template_policies) == len(target_policies):
        template_policies_to_compare = []
        target_policies_to_compare = []
        for policy in template_policies:
            # create new policy object with only relevant fields for comparison
            policy_to_compare = {'name': policy['name'], 'filter': policy['filter'], 'action': policy['action']}
            template_policies_to_compare.append(policy_to_compare)

        for policy in target_policies:
            policy_to_compare = {'name': policy['name'], 'filter': policy['filter'], 'action': policy['action']}
            # create new policy object with only relevant fields for comparison
            target_policies_to_compare.append(policy_to_compare)

        equals_policies = ordered(template_policies_to_compare) == ordered(target_policies_to_compare)

    return equals_policies


def delete_policies_from_scope(token, scope_name, target_policies, url, scope, user_key):
    """

    :rtype: object
    """
    policy_ids = []
    for policy in target_policies:
        policy_ids.append(policy["id"])

    if len(policy_ids) > 0:
        logging.info(f"  removing policies from the {scope}: {scope_name}")
        if scope == PROJECT:
            request_type = "removeProjectPolicies"
            body = {"requestType": request_type,
                    "userKey": user_key,
                    "projectToken": token,
                    "policyIds": policy_ids}
        elif scope == PRODUCT:
            request_type = "removeProductPolicies"
            body = {"requestType": request_type,
                    "userKey": user_key,
                    "productToken": token,
                    "policyIds": policy_ids}
        removed_policies = post_request(body, url)
        if removed_policies['removedPolicies'] > 0:
            logging.info(f"  {removed_policies['removedPolicies'] } policies have been deleted from the {scope} "
                         f"{scope_name}")


def add_policies_from_template_to_target(token, scope_name, template_policies, url, scope, user_key):
    """

    :rtype: object
    """
    for policy_to_add in template_policies:
        # remove from policy 'id' and 'creationTime' fields
        policy_to_add.pop("id", None)
        policy_to_add.pop("creationTime", None)
        # adding missing issue settings due to the new Issue Tracker
        policy_action = policy_to_add["action"]
        ACTION_TYPE = "CREATE_ISSUE"
        if ACTION_TYPE in policy_action["type"]:
            missing_issue_settings = {
                "issueSettings": {
                    "issueTrackerType": "COMMON_ISSUE_TRACKER"
                }
            }
            policy_action.update(missing_issue_settings)
        logging.warning(f"  adding policy {policy_to_add['name']} to the {scope} {scope_name}")
        if scope == PROJECT:
            request_type = 'addProjectPolicy'
            body = {"requestType": request_type,
                    "userKey": user_key,
                    "projectToken": token,
                    "policy": policy_to_add}
        elif scope == PRODUCT:
            request_type = 'addProductPolicy'
            body = {"requestType": request_type,
                    "userKey": user_key,
                    "productToken": token,
                    "policy": policy_to_add}
        post_request(body, url)


if __name__ == '__main__':
    main()
