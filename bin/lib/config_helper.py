# Copyright 2016 Amazon.com, Inc. or its affiliates.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#    http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

import re
import yaml
import datetime
import argparse

from troposphere import Template, Output, Export, Sub


def parse_cmdline():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-c', '--config', help='Path to config.yaml', default='./config.yaml')
    parser.add_argument(
        '-f',
        '--format',
        help='The CloudFormation format to use',
        default='json',
        choices=['json', 'yaml']
    )
    parser.add_argument(
        '-o',
        '--output-path',
        help='Path into which the CloudFormation templates will be written',
        default='./output_templates'
    )
    parser.add_argument(
        '-p',
        '--policy-path',
        help='Path to jinja2 policy templates',
        default='./policy'
    )
    args = parser.parse_args()
    return(args)


class config(object):

    # Read our config file and build a few helper constructs from it.
    def __init__(self, config_file):
        # Read our YAML
        with open(config_file, 'r') as stream:
          self.config = yaml.load(stream, Loader=yaml.FullLoader)
        # We will use our current timestamp in UTC as our build version
        self.build_version = \
            datetime.datetime.utcnow().strftime("%Y-%m-%dZ%H:%M:%S")
        # To hold our Troposphere template objects
        self.template = {}
        # A list of our accounts by names and IDs.
        self.account_ids = []
        self.account_names = []
        # A hash of IDs to names to help in forward and reverse resolution.
        self.account_map_ids = {}
        self.account_map_names = {}
        # Our parent account.
        self.parent = ""
        # SAML Provider
        self.saml_provider = ""
        for account in self.config['accounts']:
            account_id = str(self.config['accounts'][account]['id'])
            # Append to our array of account IDS:
            self.account_ids.append(account_id)
            self.account_names.append(account)
            self.account_map_names[account_id] = account
            self.account_map_ids[account] = account_id
            self.template[account] = Template()
            self.template[account].add_version("2010-09-09")
            self.template[account].add_description(
                "Build " +
                self.build_version +
                " - IAM Users, Groups, Roles, and Policies for account " +
                account +
                " (" + self.account_map_ids[account] + ")"
            )
            self.template[account].add_output([
                Output(
                    "TemplateBuild",
                    Description="CloudFormation Template Build Number",
                    Value=self.build_version,
                    Export=Export(Sub("${AWS::StackName}-" + "TemplateBuild"))
                )
            ])
            if "parent" in self.config['accounts'][account]:
                if self.config['accounts'][account]['parent'] is True:
                    self.parent_account = account
                    self.parent_account_id = account_id
                    if "saml_provider" in self.config['accounts'][account]:
                        self.saml_provider = \
                            self.config['accounts'][account]["saml_provider"]
        if self.parent_account == "":
            raise Exception(
                "No account is marked as parent in the configuration file. "
                "One account should have parent: true"
            )

    # Converts between friendly names and ids for accounts.
    def map_account(self, account):
        # If our account is numeric
        if re.match("^\d+$", account):
            return(self.account_map_names[account])
        else:
            return(self.account_map_ids[account])

    # Return an array of account names that our pattern matches
    def search_accounts(self, pattern_list=[]):

        # Make sure our pattern is actually a list.
        if not isinstance(pattern_list, list):
            raise Exception("search_accounts pattern list must be a list")

        matched = []
        # We permit a few special keywords to make our users lives easier.
        for pattern in pattern_list:
            found = False
            # If our pattern is a service name or ARN (denoted by a dot or
            # Colon we will not raise an exception about an invalid account
            # but we won't populate our matched list.
            if '.' in pattern or ':' in pattern:
                found = True
            # If our pattern is a SAML provider we will not raise an exception
            # but won't populate a match.
            if pattern == self.saml_provider:
                found = True
            if pattern == "parent":
                matched.append(self.parent_account)
                found = True
            elif pattern == "children":
                matched = list(self.config['accounts'])
                matched.remove(self.parent_account)
                found = True
            elif pattern == "all":
                matched = list(self.config['accounts'])
                found = True
            else:
                # Iterate over all of our accounts by name and by ID .
                for account_id, account_name in \
                            zip(self.account_ids, self.account_names):
                    if re.match(pattern, account_id):
                        matched.append(
                            self.map_account(account_id)
                        )
                        found = True
                    if re.match(pattern, account_name):
                        matched.append(account_name)
                        found = True

            if found is False:
                raise ValueError(
                    "Unable to find account named '{}' in the accounts: "
                    " section of the config.yaml".format(pattern)
                )

        # uniqify our matches
        matched = list(set(matched))

        return(matched)

    # is_local_* - template searches so we can deicde to Ref(), GetAtt() or
    # consider a value we see as literal.
    def is_local_user(self, user_query):
        if 'users' not in self.config:
            return(False)
        for user in self.config['users']:
            if user == user_query:
                return(True)

        return(False)

    def is_local_role(self, role_query):
        if 'roles' not in self.config:
            return(False)
        for role in self.config['roles']:
            if role == role_query:
                return(True)

        return(False)

    def is_local_group(self, group_query):
        if 'groups' not in self.config:
            return(False)
        for group in self.config['groups']:
            if group == group_query:
                return(True)

        return(False)

    def is_local_managed_policy(self, managed_policy):
        if managed_policy in self.config["policies"]:
            return True
        else:
            return False

    def is_managed_policy_in_account(self, managed_policy, account):
        if managed_policy in self.config["policies"]:
            if "in_accounts" in self.config["policies"][managed_policy]:
                policy_account_context = self.search_accounts(
                    self.config["policies"][managed_policy]["in_accounts"]
                )
                entity_account_context = self.search_accounts([account])
                if entity_account_context[0] in policy_account_context:
                    return True
                else:
                    return False
            # If there is no in_accounts section in our managed policy
            # it goes in all accounts.
            else:
                return True
