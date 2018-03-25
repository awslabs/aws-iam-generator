#!/usr/bin/env python

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

# Sample execution:
# python viz.py config-example.yaml viz-dot-template-trusts.j2 output.dot && dot -K circo -Tpng output.dot -o viz.png && open viz.png

import json
import yaml
import sys
import argparse
import re
from jinja2 import Template

class Account:

    def __init__(self, name, prop):
        self.__dict__.update(prop)
        self.name = name
        self.groups = {}
        self.users = {} # only users that are not part of a group
        self.roles = {}
        self.trusts = {}

    def add_trusts(self, role, trusted_entities):
        for entity in trusted_entities:
            if entity.name != self.name:
                if entity.name not in self.trusts:
                    self.trusts[entity.name] = [role.name]
                else:
                    self.trusts[entity.name].append(role.name)

    def add_user(self, user):
        self.users[user.name] = user

    def add_group(self, group):
        self.groups[group.name] = group

    def has_group(self, group_name):
        return group_name in self.groups

    def get_group(self, group_name):
        return self.groups[group_name]

    def add_role(self, role):
        self.roles[role.name] = role

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return self.__str__()

class Group:

    def __init__(self, name, prop):
        self.__dict__.update(prop)
        self.name = name
        self.users = {}
        self.policies = {}

    def add_user(self, user):
        self.users[user.name] = user

    def add_policy(self, policy):
        self.policies[policy.name] = policy

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return self.__str__()

class User:

    def __init__(self, name, prop):
        self.__dict__.update(prop)
        self.name = name

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return self.__str__()

class Role:

    def __init__(self, name, prop):
        self.__dict__.update(prop)
        self.name = name
        self.policies = {}

    def add_policy(self, policy):
        self.policies[policy.name] = policy

    def get_trusts(self):
        if hasattr(self, "trusts"):
            return self.trusts
        return []

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return self.__str__()

class Policy:

    def __init__(self, name, prop):
        self.__dict__.update(prop)
        self.name = name

    def is_assume_policy(self):
        return hasattr(self, "assume")

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return self.__str__()

class Resource:

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return self.__str__()

class Config:

    def __init__(self, config_file, viz_file, output_file):
        self._config_file = config_file
        self.viz_file = viz_file
        self.output_file = output_file
        self.accounts = {"all": [], "children": [], "parent": []}

    def is_account(self, name):
        return name in self.accounts

    def get_accounts(self, account_filter):
        # all, children, parent, dev, prod, etc
        if account_filter in self.accounts:
            return self.accounts[account_filter]
        # dev1., ^prod, etc
        return [a for a in self.accounts["all"]
            if re.match(account_filter, a.name)
            or re.match(account_filter, str(a.id))]

    def _create_accounts(self, accounts_dict):
        for acc_name, acc_prop in accounts_dict.items():
            account = Account(acc_name, acc_prop)
            self.accounts[acc_name] = [account]
            self.accounts["all"].append(account)
            if "parent" in acc_prop and acc_prop["parent"]:
                self.accounts["parent"] = [account]
            else:
                self.accounts["children"].append(account)

    def _create_groups(self, groups_dict, policies):
        for grp_name, grp_prop in groups_dict.items():
            for acc_name in grp_prop["in_accounts"]:
                for account in self.get_accounts(acc_name):
                    group = Group(grp_name, grp_prop)
                    account.add_group(group)
                    for policy_name in grp_prop["managed_policies"]:
                        if policy_name in policies:
                            policy = policies[policy_name]
                        else:
                            policy = Policy(policy_name, {})
                            policies[policy_name] = policy
                        group.add_policy(policy)

    def _create_users(self, users_dict):
        for user_name, user_prop in users_dict.items():
            user = User(user_name, user_prop)
            for acc_name in user_prop["in_accounts"]:
                for account in self.get_accounts(acc_name):
                    if "groups" in user_prop:
                        for group_name in user_prop["groups"]:
                            if account.has_group(group_name):
                                group = account.get_group(group_name)
                                group.add_user(user)
                            else:
                                raise "Error: cannot add user: {} to group: {} in account: {}".format(user.name, group.name, account.name)
                    else:
                        # user without a group
                        account.add_user(user)

    def _create_policies(self, policies_dict):
        policies = {}
        for pcy_name, pcy_prop in policies_dict.items():
            policies[pcy_name] = Policy(pcy_name, pcy_prop)
        return policies

    def _create_roles(self, roles_dict, policies):
        for rle_name, rle_prop in roles_dict.items():
            for acc_name in rle_prop["in_accounts"]:
                for account in self.get_accounts(acc_name):
                    role = Role(rle_name, rle_prop)
                    account.add_role(role)
                    for policy_name in rle_prop["managed_policies"]:
                        if policy_name in policies:
                            policy = policies[policy_name]
                        else:
                            policy = Policy(policy_name, {})
                            policies[policy_name] = policy
                        role.add_policy(policy)

    def _create_trusts(self):
        for account in self.accounts["all"]:
            for _, role in account.roles.items():
                for trust in role.get_trusts():
                    if self.is_account(trust):
                        trusted_accounts = self.get_accounts(trust)
                        account.add_trusts(role, trusted_accounts)
                    else:
                        account.add_trusts(role, [Resource(trust)])

    def load(self):
        try:
            with open(self._config_file, 'r') as f:
                config = yaml.load(f)
            policies = self._create_policies(config['policies'])
            self._create_accounts(config['accounts'])
            self._create_groups(config['groups'], policies)
            self._create_users(config['users'])
            self._create_roles(config['roles'], policies)
            self._create_trusts()

        except Exception as error:
                raise ValueError('Error: {} '.format(error))

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return self.__str__()

def gen_viz(config):
    try:
        with open(config.viz_file, 'r') as f:
            dot_template_content = f.read()
        template = Template(dot_template_content)
        rendered = template.render(config=config)
        with open(config.output_file, 'w') as f:
            f.write(rendered)
    except Exception as e:
        raise ValueError("Error: {}\n".format(e))

if __name__ == '__main__':

    try:
        parser = argparse.ArgumentParser(description='aws-iam-generator viz - generates dot/graphviz vizualizations for aws-iam-generator config files')
        parser.add_argument('config_file', help='config.yaml file to be vizualized')
        parser.add_argument('viz_file', help='jinja2 dot template to use to generate the vizualization')
        parser.add_argument('output_file', help='name of the output dot file')
        args = parser.parse_args()

        config = Config(args.config_file, args.viz_file, args.output_file)
        config.load()

        gen_viz(config)

        print "Successfully gerenated .dot file: {}".format(args.output_file)
        print "To vizualize the file, install graphviz (http://www.graphviz.org/) and type: 'dot -Tpng {} -o viz.png && open viz.png'".format(args.output_file)
    except Exception as e:
        print "Oops! Something went wrong: {}".format(e)
