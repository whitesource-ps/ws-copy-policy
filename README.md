![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release](https://img.shields.io/github/v/release/whitesource-ps/ws-copy-policy)](https://github.com/whitesource-ps/ws-copy-policy/releases/latest)
[![WS Copy Policy Build and Publish](https://github.com/whitesource-ps/ws-copy-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-copy-policy/actions/workflows/ci.yml)
[![Python 3.6](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)


# WhiteSource copy policy tool
The script allows copying policies automatically, from the template project/product to the newly created projects/products, and update existing projects with the template policy.
It should run periodically, in order to make sure that all the policies under the required projects/products are up to date.

### How to use the script
1. Create an empty project/product or few with the required template policy.
2. Tag an empty project/product with the following project tag: `key=Policy.Template.Source,  value=<yourUniqueTemplateName>`.
3. For a new project/product creation that requires the template policy, add the following project/product tag: `key=Policy.Template.Destination, value=<yourUniqueTemplateName>`. It can be added via the UI or as part of the Unified Agent run.
4. The template policy will be updated for the required projects/products.
   **Note:** Make sure that the tag `Policy.Template.Source` value is unique and is presented only in one project/product.

### What does the script do?
For each project/product in the system, the script extracts the Tag key called: `Policy.Template.Source`, and the tag key called `Policy.Template.Destination`. 
In the event, the tag value of the project/product with `Policy.Template.Source` tag key equals the tag value of the project/product with `Policy.Template.Destination` tag key, the script will do the following:
- Delete the existing policies from the project/product with `Policy.Template.Destination` tag key.
- Copy the project/product policies of the project/product with `Policy.Template.Source` tag key to the project/product with `Policy.Template.Destination` tag key.


### Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016

### Prerequisites
- Python 3.6 or above

## Installation and Execution by pulling package from PyPi:
1. Execute `pip install ws-copy-policy`
* **Note**:  If installing packages as a non-root be sure to include the path to the executables within the Operating System paths.
2. Run report:
   `ws-copy-policy -u <URL> -k <USER_KEY> -o <ORG_TOKEN> -s <COPY_SCOPE> -t <THREAD_NUMBER>`
   or
   `ws-copy-policy <CONFIG_FILE_PATH>`
* **Note**:  If installing packages as a non-root be sure to include the path to the executables within the Operating System paths.

### Configuration Parameters
```
===============================================================================================================
| Group         | Parameter            | Description                                                          |
===============================================================================================================
| DEFAULT       | wsUrl                | WhiteSource server URL. Can be found under the 'Integrate' tab in    |   
|               |                      | your WhiteSource organization.                                       |
---------------------------------------------------------------------------------------------------------------
| DEFAULT       | userKey              | WhiteSource User Key. Can be found under the 'Profile' section in    |
|               |                      | your WhiteSource organization.                                       |
---------------------------------------------------------------------------------------------------------------
| DEFAULT       | orgToken             | WhiteSource API Key. Can be found under the 'Integrate' tab in your  |
|               |                      | your WhiteSource organization.                                       |
---------------------------------------------------------------------------------------------------------------
| DEFAULT       | scope                | The scope where the copying policies should be performed on.         |
|               |                      | Possible values: project/product.                                    |
---------------------------------------------------------------------------------------------------------------
| DEFAULT       | thread               | Multi-threading - speeds up the copying, but it depends              |
|               |                      | on your environment capabilities (default: 5).                       |
===============================================================================================================
```

### Author
WhiteSource Software ©


