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

import re
import json
import yaml
import jinja2

from troposphere import Output, GetAtt, Ref, Export, Sub, ImportValue
from troposphere.iam import Role, ManagedPolicy, Group, User
from troposphere.iam import InstanceProfile, LoginProfile
from lib.config_helper import config, parse_cmdline


# CloudFormation names must be alphanumeric.
# Our config might include non-alpha, so we'll scrub them here.
def scrub_name(name):
    return(re.sub('[\W_]+', '', name))


# Creates a policy document from a jinja template
def policy_document_from_jinja(c, policy_name, model, policy_path, policy_format):

    # Try and read the policy file file into a jinja template object
    try:
        template = jinja2.Environment(loader=jinja2.FileSystemLoader(policy_path)) \
                         .get_template(model["policy_file"])
    except Exception as e:
        raise ValueError(
            "Failed to read template file {}/{}\n\n{}".format(
                policy_path,
                model["policy_file"],
                e
            )
        )

    # Perform our jinja substitutions on the file contents.
    template_vars = ""
    if "template_vars" in model:
        template_vars = model["template_vars"]

    try:
        template_jinja = template.render(
            config=c.config,
            account=c.map_account(c.current_account),
            parent_account=c.parent_account_id,
            template_vars=template_vars
        )
    except Exception as e:
        raise ValueError(
            "Jinja render failure working on file {}/{}\n\n{}".format(
                policy_path,
                model["policy_file"],
                e
            )
        )

    # Now encode the jinja parsed template as JSON or YAML
    try:
        doc = json.loads(template_jinja) if policy_format == 'json' else yaml.load(template_jinja)
    except Exception as e:
        print("Contents returned after Jinja parsing:\n{}".format(template_jinja))
        raise ValueError(
            "{} encoding failure working on file {}/{}\n\n{}".format(
                policy_format.upper(),
                policy_path,
                model["policy_file"],
                e
            )
        )

    return(doc)


def build_role_trust(c, trusts):
    policy = {
        "Version":  "2012-10-17",
        "Statement": [],
    }

    valid_web_principals = [
        "cognito-identity.amazonaws.com",
        "www.amazon.com",
        "graph.facebook.com",
        "accounts.google.com",
    ]

    service_principals = []
    aws_principals = []
    saml_principals = []
    web_principals = []

    for trust in trusts:
        # See if we match an account:
        # First see if we match an account friendly name.
        trust_account = ""
        try:
            trust_account = c.search_accounts([trust])
        except Exception:
            pass
        if trust_account:
            aws_principals.append(
                "arn:aws:iam::"
                + str(c.account_map_ids[trust_account[0]])
                + ":root"
            )
        # See if this is a user inside the template
        elif c.is_local_user(trust):
            aws_principals.append(
                GetAtt(scrub_name("{}User".format(trust)), "Arn")
            )
        # See if this is a group inside the template
        elif c.is_local_group(trust):
            aws_principals.append(
                GetAtt(scrub_name("{}Group".format(trust)), "Arn")
            )
        # See if this is a role inside the template
        elif c.is_local_role(trust):
            aws_principals.append(
                GetAtt(scrub_name("{}Role".format(trust)), "Arn")
            )
        # Next see if we match our SAML trust.
        elif trust == c.saml_provider:
            saml_principals.append(
                "arn:aws:iam::"
                + c.parent_account_id
                + ":saml-provider/"
                + c.saml_provider
            )
        # See if we match a user, group, or role ARN Principal
        elif re.match("arn:aws:iam::\d{12}:(user|group|role)/.*?", trust) or \
                re.match("arn:aws:sts::\d{12}:assumed-role/.*?/.*?", trust):
            aws_principals.append(trust)
        # See if we have a service
        elif re.match("^.*\.amazonaws\.com$", trust):
            service_principals.append(trust)
        # See if we have a web federation principal
        elif trust in valid_web_principals:
            web_principals.append(trust)
        # Otherwise raise a value-error
        else:
            raise ValueError(
                "Trust name '{}' in the config.yaml does not appear to be "
                "valid.  Confirm it is a valid AWS Principal ARN / AWS "
                "Service Principal or an Account Name / SAML Provider "
                "contained in the config.yaml".format(
                    trust
                )
            )

    if aws_principals:
        policy["Statement"].append({
            "Effect": "Allow",
            "Principal": {"AWS": aws_principals},
            "Action": "sts:AssumeRole"
        })

    if service_principals:
        policy["Statement"].append({
            "Effect": "Allow",
            "Principal": {"Service": service_principals},
            "Action": "sts:AssumeRole"
        })

    if saml_principals:
        policy["Statement"].append({
            "Effect": "Allow",
            "Principal": {"Federated": saml_principals},
            "Action": "sts:AssumeRoleWithSAML",
            "Condition": {
                "StringEquals": {
                   "SAML:aud": "https://signin.aws.amazon.com/saml"
                }
            }
        })

    if web_principals:
        policy["Statement"].append({
            "Effect": "Allow",
            "Principal": {"Federated": web_principals},
            "Action": "sts:AssumeRoleWithWebIdentity"
        })

    return(policy)


def build_assume_role_policy_document(c, accounts, roles):
    policy_statement = {
        "Version": "2012-10-17",
        "Statement": []
    }
    for role in roles:
        for account in accounts:
            policy_statement["Statement"].append(
                build_sts_statement(c.map_account(account), role)
            )

    return(policy_statement)


def build_sts_statement(account, role):
    statement = {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "arn:aws:iam::" + account + ":role/" + role,
    }
    return(statement)


# Managed policies are unique in that they must be an ARN.
# So either we have an ARN, or a Ref() within our current environment
# or an import: statement from another cloudformation template.
def parse_managed_policies(c, managed_policies, working_on):
    managed_policy_list = []
    for managed_policy in managed_policies:
        # If we have an ARN then we're explicit
        if re.match(r"^arn:", managed_policy):
            if re.search(r"\${[^}]+}", managed_policy):
                managed_policy_list.append(Sub(managed_policy))
            else:
                managed_policy_list.append(managed_policy)
        # If we have an import: then we're importing from another template.
        elif re.match("^import:", managed_policy):
            m = re.match("^import:(.*)", managed_policy)
            managed_policy_list.append(ImportValue(m.group(1)))
        # Alternately we're dealing with a managed policy locally that
        # we need to 'Ref' to get an ARN.
        else:
            # Confirm this is a local policy, otherwise we'll error out.
            if c.is_local_managed_policy(managed_policy):
                # Policy name exists in the template,
                # lets make sure it will exist in this account.
                if c.is_managed_policy_in_account(
                        managed_policy,
                        c.map_account(c.current_account)
                ):
                    # If this is a ref we'll need to assure it's scrubbed
                    managed_policy_list.append(Ref(scrub_name(managed_policy)))
                else:
                    raise ValueError(
                        "Working on: '{}' - Managed Policy: '{}' "
                        "is not configured to go into account: '{}'".format(
                            working_on,
                            managed_policy,
                            c.current_account
                        )
                    )
            else:
                raise ValueError(
                    "Working on: '{}' - Managed Policy: '{}' "
                    "does not exist in the configuration file".format(
                        working_on,
                        managed_policy
                    )
                )

    return(managed_policy_list)


# We use this over users/groups/roles:
# - Check if we have an import: syntax in use.
# - Under a 'user' context' a local 'group' can be referenced.  If we're
#   operating as named = false the group name won't match the template name
#   so we need to assure we use a 'Ref' in that scenario.
def parse_imports(c, context, element_list):
    return_list = []
    for element in element_list:
        # See if we match an import
        if re.match("^import:", element):
            m = re.match("^import:(.*)", element)
            return_list.append(ImportValue(m.group(1)))
        # See if we match a group in the template.  If so we need to Ref()
        # the group name for named: false to work.
        elif c.is_local_group(element) and context == "user":
            return_list.append(Ref(scrub_name("{}Group".format(element))))
        # Otherwise we're verbatim as there's no real way to know if this
        # is within the template or existing.
        else:
            return_list.append(element)

    return(return_list)


def add_managed_policy(
        c,
        ManagedPolicyName,
        PolicyDocument,
        model,
        named=False
        ):
    cfn_name = scrub_name(ManagedPolicyName)
    kw_args = {
        "Description": "Managed Policy " + ManagedPolicyName,
        "PolicyDocument": PolicyDocument,
        "Groups": [],
        "Roles": [],
        "Users": []
    }

    if named:
        kw_args["ManagedPolicyName"] = ManagedPolicyName
    if "description" in model:
        kw_args["Description"] = model["description"]
    if "groups" in model:
        kw_args["Groups"] = parse_imports(c, "policy", model["groups"])
    if "users" in model:
        kw_args["Users"] = parse_imports(c, "user", model["users"])
    if "roles" in model:
        kw_args["Roles"] = parse_imports(c, "role", model["roles"])

    if "retain_on_delete" in model:
        if model["retain_on_delete"] is True:
            kw_args["DeletionPolicy"] = "Retain"

    c.template[c.current_account].add_resource(ManagedPolicy(
        cfn_name,
        **kw_args
    ))

    if c.config['global']['template_outputs'] == "enabled":
        c.template[c.current_account].add_output([
            Output(
                cfn_name + "PolicyArn",
                Description=kw_args["Description"] + " Policy Document ARN",
                Value=Ref(cfn_name),
                Export=Export(Sub(
                        "${AWS::StackName}-"
                        + cfn_name
                        + "PolicyArn"
                        ))
            )
        ])


def create_instance_profile(c, RoleName, model, named=False):
    cfn_name = scrub_name(RoleName + "InstanceProfile")

    kw_args = {
        "Path": "/",
        "Roles": [Ref(scrub_name(RoleName + "Role"))]
    }

    if named:
        kw_args["InstanceProfileName"] = RoleName

    if "retain_on_delete" in model:
        if model["retain_on_delete"] is True:
            kw_args["DeletionPolicy"] = "Retain"

    c.template[c.current_account].add_resource(InstanceProfile(
        cfn_name,
        **kw_args
    ))

    if c.config['global']['template_outputs'] == "enabled":
        c.template[c.current_account].add_output([
            Output(
                cfn_name + "Arn",
                Description="Instance profile for Role " + RoleName + " ARN",
                Value=Ref(cfn_name),
                Export=Export(Sub("${AWS::StackName}-" + cfn_name + "Arn"))
            )
        ])


def add_role(c, RoleName, model, named=False):
    cfn_name = scrub_name(RoleName + "Role")
    kw_args = {
        "Path": "/",
        "AssumeRolePolicyDocument": build_role_trust(c, model['trusts']),
        "ManagedPolicyArns": [],
        "Policies": []
    }

    if named:
        kw_args["RoleName"] = RoleName

    if "managed_policies" in model:
        kw_args["ManagedPolicyArns"] = parse_managed_policies(
                                        c, model["managed_policies"], RoleName)

    if "max_role_duration" in model:
        kw_args['MaxSessionDuration'] = int(model["max_role_duration"])

    if "retain_on_delete" in model:
        if model["retain_on_delete"] is True:
            kw_args["DeletionPolicy"] = "Retain"

    c.template[c.current_account].add_resource(Role(
        cfn_name,
        **kw_args
    ))
    if c.config['global']['template_outputs'] == "enabled":
        c.template[c.current_account].add_output([
            Output(
                cfn_name + "Arn",
                Description="Role " + RoleName + " ARN",
                Value=GetAtt(cfn_name, "Arn"),
                Export=Export(Sub("${AWS::StackName}-" + cfn_name + "Arn"))
            )
        ])


def add_group(c, GroupName, model, named=False):
    cfn_name = scrub_name(GroupName + "Group")
    kw_args = {
        "Path": "/",
        "ManagedPolicyArns": [],
        "Policies": []
    }

    if named:
        kw_args["GroupName"] = GroupName

    if "managed_policies" in model:
        kw_args["ManagedPolicyArns"] = parse_managed_policies(
            c,
            model["managed_policies"], GroupName
        )

    if "retain_on_delete" in model:
        if model["retain_on_delete"] is True:
            kw_args["DeletionPolicy"] = "Retain"

    c.template[c.current_account].add_resource(Group(
        scrub_name(cfn_name),
        **kw_args
    ))
    if c.config['global']['template_outputs'] == "enabled":
        c.template[c.current_account].add_output([
            Output(
                cfn_name + "Arn",
                Description="Group " + GroupName + " ARN",
                Value=GetAtt(cfn_name, "Arn"),
                Export=Export(Sub("${AWS::StackName}-" + cfn_name + "Arn"))
            )
        ])


def add_user(c, UserName, model, named=False):
    cfn_name = scrub_name(UserName + "User")
    kw_args = {
        "Path": "/",
        "Groups": [],
        "ManagedPolicyArns": [],
        "Policies": [],
    }

    if named:
        kw_args["UserName"] = UserName

    if "groups" in model:
        kw_args["Groups"] = parse_imports(c, "user", model["groups"])

    if "managed_policies" in model:
        kw_args["ManagedPolicyArns"] = parse_managed_policies(
                c,
                model["managed_policies"],
                UserName
            )

    if "password" in model:
        kw_args["LoginProfile"] = LoginProfile(
            Password=model["password"],
            PasswordResetRequired=True
        )

    if "retain_on_delete" in model:
        if model["retain_on_delete"] is True:
            kw_args["DeletionPolicy"] = "Retain"

    c.template[c.current_account].add_resource(User(
        cfn_name,
        **kw_args
    ))
    if c.config['global']['template_outputs'] == "enabled":
        c.template[c.current_account].add_output([
            Output(
                cfn_name + "Arn",
                Description="User " + UserName + " ARN",
                Value=GetAtt(cfn_name, "Arn"),
                Export=Export(Sub("${AWS::StackName}-" + cfn_name + "Arn"))
            )
        ])


def main():
    args = parse_cmdline()

    try:
        c = config(args.config)
    except Exception as e:
        raise ValueError(
            "Failed to parse the YAML Configuration file. "
            "Check your syntax and spacing!\n\n{}".format(e)
        )

    # We introduced a 'global' section to control naming now that we have more
    # control over naming via CloudFormation.  To be backward compatible with
    # older config.yamls that don't have a config.yaml we'll set our values
    # to our previous implied functionality (named values for all but managed
    # policies).
    if 'global' not in c.config:
        c.config['global'] = {
            "names": {
                "policies": False,
                "roles": True,
                "users": True,
                "groups": True
            },
            "template_outputs": "enabled"
        }

    # Policies
    if "policies" in c.config:
        for policy_name in c.config["policies"]:

            context = ["all"]
            if "in_accounts" in c.config["policies"][policy_name]:
                context = c.config["policies"][policy_name]["in_accounts"]

            for account in c.search_accounts(context):
                c.current_account = account
                # If our managed policy is jinja based we'll have a policy_file
                policy_document = ""
                if "policy_file" in c.config["policies"][policy_name]:
                    policy_document = policy_document_from_jinja(
                        c,
                        policy_name,
                        c.config["policies"][policy_name],
                        args.policy_path,
                        args.format
                    )
                # If our managed policy is generated as an assume trust
                # we'll have assume
                if "assume" in c.config["policies"][policy_name]:
                    policy_document = build_assume_role_policy_document(
                        c,
                        c.search_accounts(
                            c.config["policies"][policy_name]["assume"]["accounts"]
                        ),
                        c.config["policies"][policy_name]["assume"]["roles"]
                    )

                add_managed_policy(
                    c,
                    policy_name,
                    policy_document,
                    c.config["policies"][policy_name],
                    c.config["global"]["names"]["policies"]
                )

    # Roles
    if "roles" in c.config:
        for role_name in c.config["roles"]:
            context = ["all"]
            if "in_accounts" in c.config["roles"][role_name]:
                context = c.config["roles"][role_name]["in_accounts"]

            for account in c.search_accounts(context):
                c.current_account = account
                add_role(
                    c,
                    role_name,
                    c.config["roles"][role_name],
                    c.config["global"]["names"]["roles"]
                )

                # See if we need to add an instance profile too with an ec2 trust.
                if "ec2.amazonaws.com" in c.config["roles"][role_name]["trusts"]:
                    create_instance_profile(
                        c,
                        role_name,
                        c.config["roles"][role_name],
                        c.config["global"]["names"]["roles"]
                    )

    # Groups
    if "groups" in c.config:
        for group_name in c.config["groups"]:

            context = ["all"]
            if "in_accounts" in c.config["groups"][group_name]:
                context = c.config["groups"][group_name]["in_accounts"]

            for account in c.search_accounts(context):
                c.current_account = account
                add_group(
                    c,
                    group_name,
                    c.config["groups"][group_name],
                    c.config["global"]["names"]["groups"]
                )

    # Users
    if "users" in c.config:
        for user_name in c.config["users"]:

            context = ["all"]
            if "in_accounts" in c.config["users"][user_name]:
                context = c.config["users"][user_name]["in_accounts"]

            for account in c.search_accounts(context):
                c.current_account = account
                add_user(
                    c,
                    user_name,
                    c.config["users"][user_name],
                    c.config["global"]["names"]["users"]
                )

    for account in c.search_accounts(["all"]):
        fh = open(
            args.output_path
            + "/" + account
            + "(" + c.account_map_ids[account]
            + ")-IAM.template", 'w'
        )

        data = c.template[account].to_json() if args.format == 'json' else c.template[account].to_yaml()
        fh.write(data)
        fh.close()


if __name__ == '__main__':
    main()
