import argparse
import sys
import logging
from configparser import ConfigParser
import requests
import json
from copy import deepcopy

LOG_DIR = 'logs'
LOG_FILE_WITH_PATH = LOG_DIR + '/ws-copy-policy.log'
PROJECT = 'project'
PRODUCT = 'product'
user_key = ''
org_token = ''
url = ''
scope = None
logger = logging.getLogger()


class Configuration:
    def __init__(self):
        config = ConfigParser()
        config.optionxform = str
        config.read('./config/params.config')
        # WS Settings
        self.url = config.get('DEFAULT', 'wsUrl')
        self.user_key = config.get('DEFAULT', 'userKey')
        self.org_token = config.get('DEFAULT', 'orgToken')
        self.scope = config.get('DEFAULT', 'scope')


class ArgumentsParser:
    def __init__(self):
        """

        :return:
        """
        parser = argparse.ArgumentParser(description="Description for my parser")
        parser.add_argument("-u", required=False)
        parser.add_argument("-k", required=False)
        parser.add_argument("-o", required=False)
        parser.add_argument("-s", required=False)

        argument = parser.parse_args()
        if argument.u:
            self.url = argument.u
        if argument.k:
            self.user_key = argument.k
        if argument.o:
            self.org_token = argument.o
        if argument.s:
            self.scope = argument.s


def main():

    global user_key
    global org_token
    global url
    global scope

    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    logging.info("Starting")
    logging.info("Validating parameters")

    args = sys.argv[1:]
    if len(args) >= 8:
        config = ArgumentsParser()
    else:
        config = Configuration()

    org_token = config.org_token
    user_key = config.user_key
    url = config.url
    scope = config.scope
    if scope != PROJECT and scope != PRODUCT:
        logging.error("scope should be 'project' or 'product'. Please check input parameters and try again.")
        exit(1)
    logging.info("Using url %s", url)
    get_policies()

    logging.info("Status: SUCCESS")
    sys.exit(0)


def get_policies():
    """

    """
    # getOrganizationProjectTags api
    if scope == PROJECT:
        request_type = "getOrganizationProjectTags"
    elif scope == PRODUCT:
        request_type = "getOrganizationProductTags"
    body = {"requestType": request_type,
            "userKey": user_key,
            "orgToken": org_token}
    scope_tags = post_request(request_type, body)
    template_value_to_policies = {}
    scope_token_to_template_value_and_policies = {}
    fill_template_values_and_projects_from_response(scope_tags, template_value_to_policies,
                                                    scope_token_to_template_value_and_policies)

    scope_size = len(scope_token_to_template_value_and_policies)
    size_of_finished_copies = 0
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
                delete_policies_from_scope(token, scope_name, target_policies)
                logging.info(f"Adding policies from the template {scope} {template_value} "
                             f"to the destination {scope} {scope_name}")
                add_policies_from_template_to_target(token, scope_name, template_policies)
            else:
                logging.info(f"{scope} {scope_name} has a template destination value {template_value}, but it "
                             f"already contains the same policies. Skip to the next {scope}.")
        else:
            logging.warning(f"{scope} {scope_name} has key value of the  {template_value}, "
                            f"but there is no {scope} with this key value. Skip to the next item.")
        size_of_finished_copies = size_of_finished_copies + 1
        logging.info(f"Finish handling {size_of_finished_copies} out of the {scope_size} {scope}s")


def post_request(request_type, body):
    """

    :param request_type:
    :param body:
    :return:
    """
    logging.info(f"Start {request_type} api", )
    headers = {'content-type': 'application/json'}
    response = requests.post(url, data=json.dumps(body), headers=headers)
    logging.info(f"Finish {request_type} api", )
    response_object = json.loads(response.text)
    check_errors_in_response(response_object)
    return response_object


def check_errors_in_response(response):
    """

    :param response:
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
                                                    scope_token_to_template_value_and_policies):
    """

    :param response:
    :param template_value_to_policies:
    :param scope_token_to_template_value_and_policies:
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
        for scope_item in scope_array:
            tags = scope_item["tags"]
            scope_token = scope_item["token"]
            if scope == PROJECT:
                body["projectToken"] = scope_token
            if scope == PRODUCT:
                body["productToken"] = scope_token
            scope_policies = post_request(request_type, body)
            if tag_template_key in tags:
                logging.info(f"Found template {scope_item['name']}. Key value: {tags[tag_template_key]}")
                # getProjectPolicies api
                template_value_to_policies[tags[tag_template_key]] = scope_policies["policies"]
            elif tag_scope_set_policies_key in tags:
                logging.info(f"Found target {scope} {scope_item['name']}. Key value: {tags[tag_scope_set_policies_key]}")
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

    :param template_policies:
    :param target_policies:
    :return:
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


def delete_policies_from_scope(token, scope_name, target_policies):
    """

    :param token:
    :param scope_name:
    :param target_policies:
    """
    policy_ids = []
    for policy in target_policies:
        policy_ids.append(policy["id"])

    if len(policy_ids) > 0:
        logging.info(f"Remove policies from {scope}: {scope_name}")
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
        removed_policies = post_request(request_type, body)
        if removed_policies['removedPolicies'] > 0:
            logging.info(f"{removed_policies['removedPolicies'] } policies has been deleted from the {scope_name}")


def add_policies_from_template_to_target(token, project_name, template_policies):
    """

    :param token:
    :param project_name:
    :param template_policies:
    """
    for policyToAdd in template_policies:
        # remove from policy 'id' and 'creationTime' fields
        policyToAdd.pop("id", None)
        policyToAdd.pop("creationTime", None)
        logging.info("Adding policy '%s'", policyToAdd["name"])
        if scope == PROJECT:
            request_type = 'addProjectPolicy'
            body = {"requestType": request_type,
                    "userKey": user_key,
                    "projectToken": token,
                    "policy": policyToAdd}
        elif scope == PRODUCT:
            request_type = 'addProductPolicy'
            body = {"requestType": request_type,
                    "userKey": user_key,
                    "productToken": token,
                    "policy": policyToAdd}

        post_request(request_type, body)

    logging.info(f"Finish adding policies to the {scope} {project_name}")


if __name__ == '__main__':
    main()
