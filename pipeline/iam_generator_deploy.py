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

import os
import re
import json
import boto3
import zipfile
from botocore.client import Config


# Creates our session and client boto objects.
def build_clients(account_id, name, rolename, region="ca-central-1"):

    session = boto3.session.Session()

    sts_client = session.client('sts')

    response = sts_client.assume_role(
        RoleArn="arn:aws:iam::{}:role/{}".format(
            account_id,
            rolename
        ),
        RoleSessionName=rolename,
        DurationSeconds=900,
    )

    credentials = response['Credentials']

    client = session.client(
        name,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )

    resource = session.resource(
        name,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )

    return(client, resource)


def boto3_agent_from_sts(agent_service, agent_type, region, credentials={}):

    session = boto3.session.Session()

    # Generate our kwargs to pass
    kw_args = {
        "region_name": region,
        "config": Config(signature_version='s3v4')
    }

    if credentials:
        kw_args["aws_access_key_id"] = credentials['accessKeyId']
        kw_args["aws_secret_access_key"] = credentials['secretAccessKey']
        kw_args["aws_session_token"] = credentials['sessionToken']

    # Build our agent depending on how we're called.
    if agent_type == "client":
        return(session.client(
            agent_service,
            **kw_args
        ))
    if agent_type == "resource":
        return(session.resource(
            agent_service,
            **kw_args
        ))


def deploy_stack(cfn_c, stack_name, template, capabilities=[]):

        kw_args = {
            "StackName": stack_name,
        }

        if template.startswith("http"):
            kw_args["TemplateURL"] = template
        else:
            kw_args["TemplateBody"] = template

        if len(capabilities) > 0:
            kw_args["Capabilities"] = capabilities

        stack_exists = True
        try:
            cfn_c.describe_stacks(
                StackName=stack_name
            )
        except Exception:
            stack_exists = False

        if stack_exists:
            cfn_c.update_stack(
                **kw_args
            )
            return(
                cfn_c.get_waiter(
                    "stack_update_complete"
                )
            )
        else:
            cfn_c.create_stack(
                **kw_args
            )
            return(
                cfn_c.get_waiter(
                    "stack_create_complete"
                )
            )


def wait_for_stacks(waiters):

    for waiter in waiters:
        print "Waiting for stack: {} account: {} region: {}".format(
            waiter['stack'],
            waiter['account_id'],
            waiter['region']
        )
        try:
            waiter['waiter'].wait(
                StackName=waiter['stack']
            )
        except Exception:
            raise RuntimeError(
                "Deploy Failed: stack: {} account: {} region: {}".format(
                    waiter['stack'],
                    waiter['account_id'],
                    waiter['region']
                )
            )


def determine_region(context):

    m = re.match("arn:aws:lambda:(.*?):\d+.*$", context.invoked_function_arn)
    if m:
        return(m.group(1))
    else:
        raise RuntimeError(
            "Could not determine region from arn {}".format(
                context.invoked_function_arn
            )
        )


def main(event, context):

    print "Raw event: " + json.dumps(event)

    local_region = determine_region(context)

    # CodePipeline agent so we can send an exception.
    cp_c = boto3_agent_from_sts("codepipeline", "client", local_region)

    try:
        # Extract our credentials and locate our artifact from our build.
        credentials = event['CodePipeline.job']['data']['artifactCredentials']
        artifact_s3_r = boto3_agent_from_sts(
            "s3",
            "resource",
            local_region,
            credentials
        )

        input_artifact = \
            event['CodePipeline.job']['data']['inputArtifacts'][0]
        artifact_location = input_artifact['location']['s3Location']

        artifact_s3_r.meta.client.download_file(
            artifact_location['bucketName'],
            artifact_location['objectKey'],
            "/tmp/artifact"
        )

        s3_c = boto3_agent_from_sts(
            "s3",
            "client",
            os.environ["deployment_region"]
        )

        artifacts = {}
        # We need to move our CFN artifacts from our build bucket
        # to our deployment bucket which is accessible by all accounts
        # we will deploy to.
        # ZipFile supports opening a filehandle so we can copy using
        # the upload_fileobj() method.
        zf = zipfile.ZipFile('/tmp/artifact')
        for filename in zf.namelist():
            # Skip anything in our artifact that doesn't end in .template
            if not filename.endswith(".template"):
                continue
            # Determine the account name and populate our status dictionary.
            m = re.match("^.*\((\d+)\).*\.template$", filename)
            if m:
                account_id = m.group(1)
                artifacts[account_id] = {
                    "template_url": "https://s3.{}.amazonaws.com/{}/{}/{}".format(
                        os.environ["deployment_region"],
                        os.environ["deployment_bucket"],
                        os.environ["deployment_key_prefix"],
                        filename
                    )
                }
            else:
                raise ValueError(
                    "Cannot derive account number from filename {}".format(
                        filename
                    )
                )
            # Copy our build objects to our deployment bucket.
            s3_c.upload_fileobj(
                zf.open(filename),
                os.environ["deployment_bucket"],
                '{}/{}'.format(
                    os.environ["deployment_key_prefix"],
                    filename
                )
            )

        waiters = []
        for account_id in artifacts:
            (cfn_c, cfn_r) = build_clients(
                account_id,
                "cloudformation",
                os.environ['assume_role'],
                region=os.environ["deployment_region"]
            )

            waiter = deploy_stack(
                cfn_c,
                os.environ["stack_name"],
                artifacts[account_id]['template_url'],
                ["CAPABILITY_NAMED_IAM"]
            )

            waiters.append({
                "stack": os.environ['stack_name'],
                "account_id": account_id,
                "region": os.environ['deployment_region'],
                "waiter": waiter
            })

        # Stacks are deployed, lets call our waiters
        wait_for_stacks(waiters)

        cp_c.put_job_success_result(
            jobId=event['CodePipeline.job']['id'],
            executionDetails={
                'summary': "Successful deployment",
                'percentComplete': 100
            }
        )

    except Exception as e:
        cp_c.put_job_failure_result(
            jobId=event['CodePipeline.job']['id'],
            failureDetails={
                'type': 'JobFailed',
                'message': 'Exception: {}'.format(e)
            }
        )
        raise


def lambda_handler(event, context):

    main(event, context)


def outside_lambda_handler():

    class context(object):
        def __init__(self, **kwargs):
            self.function_name = kwargs.get(
                "function_name",
                "centralPolicyAudit"
            )
            self.invoked_function_arn = kwargs.get(
                "invoked_function_arn",
                "arn:aws:lambda:us-east-1:443888193270"
                + ":function:centralPolicyAudit"
            )
            self.log_group_name = kwargs.get(
                "log_group_name",
                "/aws/lambda/centralPolicyAudit"
            )
            self.log_stream_name = kwargs.get(
                "log_stream_name",
                "2017/05/23/[$LATEST]7ea52202c1494810ab5713f045697b4f"
            )

    context = context()

    # For development outside of Lambda.
    # Paste the event from codepipeline.
    event = json.loads("""
{ "CodePipeline.job": { "data": { "artifactCredentials": { "secretAccessKey": "", "accessKeyId": "", "sessionToken": "" }, "actionConfiguration": { "configuration": { "FunctionName": "iam_generator_deploy" } }, "inputArtifacts": [ { "location": { "type": "S3", "s3Location": { "objectKey": "", "bucketName": "" } }, "name": "MyAppBuild", "revision": null } ], "outputArtifacts": [] }, "id": "", "accountId": "" } }
    """)

    main(event, context)


if __name__ == '__main__':
    outside_lambda_handler()
