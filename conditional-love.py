#!/usr/bin/env python3
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError
import requests
import json
from argparse import ArgumentParser


SUPPORTED_CONDITIONS = [
    's3:ResourceAccount', 
    'aws:ResourceAccount', 
    'aws:ResourceOrgPaths', 
    'aws:ResourceOrgID', 
    'aws:ResourceTag',
    'lambda:FunctionArn'
]
SUPPORTED_ACTIONS = [
    's3:HeadObject', 
    'dataexchange:GetDataSet', 
    'lambda:InvokeFunctionUrl', 
    'execute-api:Invoke',
    'sts:AssumeRole',
    'sqs:ReceiveMessage',
]

def main(args):
    base_session = get_base_session(args.profile)

    if not can_access_target_with_policy(base_session, args.role, args.target, args.action, None, args.region):
        print(f"Failed to access target. Exiting.")
        exit(1)

    print("Starting to be wrong. Please be patient...")
    run_search(base_session, args)



def run_search(base_session, args):
    confirmed_partial = ""

    for _ in range(0, 100):
        for i, alpha in enumerate(args.alphabet):
            test_partial = f"{confirmed_partial}{alpha}"
            policy = get_policy(args.action, args.condition, test_partial, args.tag_key)
            if can_access_target_with_policy(base_session, args.role, args.target, args.action, json.dumps(policy), args.region):
                print(f"=> {test_partial}")
                confirmed_partial = test_partial
                break
        if confirmed_partial != test_partial:
            break


def get_policy(action, condition, partial, tag_key=None):
    if condition == 'aws:ResourceTag':
        condition = f"aws:ResourceTag/{tag_key}"

    service_name = action.split(':')[0]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowResourceAccount",
                "Effect": "Allow",
                "Action": [f"{service_name}:*"],
                "Resource": "*",
                "Condition": {
                    "StringLike": {condition: [f"{partial}*"]},
                },
            },
        ],
    }
    return policy


def get_base_session(profile):
    if profile:
        return boto3.Session(profile_name=profile)
    else:
        return boto3.Session()
    

def can_access_target_with_policy(session, role_arn, target, action, policy=None, region=None):
    if not policy:
        assumed_role_session = assume_role(session, role_arn)
    else:
        assumed_role_session = assume_role(session, role_arn, Policy=policy)

    service_name = action.split(':')[0]
    # Lambda and API gateway execution uses a URL rather than a boto client
    if service_name not in ['execute-api', 'lambda']:
        if not region:
            client = assumed_role_session.client(service_name)
        else:
            client = assumed_role_session.client(service_name, region_name=region)
    
    try:
        if action=='s3:HeadObject':
            head_s3_object(client, target)
        elif action=='dataexchange:GetDataSet':
            client.get_data_set(DataSetId=target)
        elif action=='lambda:InvokeFunctionUrl':
            return invoke_lambda_url(assumed_role_session, target, region)
        elif action=='execute-api:Invoke':
            return invoke_apigateway_url(assumed_role_session, target, region)
        elif action=='sts:AssumeRole':
            client.assume_role(RoleArn=target, RoleSessionName='ConditionalLoveSession')
        elif action=='sqs:ReceiveMessage':
            client.receive_message(QueueUrl=target)

        return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in [
            "AccessDeniedException",
            "ForbiddenException",
            "ForbiddenException, AccessDeniedException",
            "403",
        ]:
            pass
        
    return False


def assume_role(session, role_arn, Policy=None):
    assumed_session = None
    try:
        assume_role_kwargs = {
            'RoleArn': role_arn,
            'RoleSessionName': 'ConditionalLoveSession'
        }
        if Policy:
            assume_role_kwargs['Policy'] = Policy

        sts_client = session.client('sts')
        assumed_role = sts_client.assume_role(**assume_role_kwargs)

        # Use the temporary credentials that AssumeRole returns to create a session
        assumed_session = boto3.Session(
            aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
            aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
            aws_session_token=assumed_role['Credentials']['SessionToken']
        )
    except ClientError as e:
        print("Failed to assume role: ", e)
    
    return assumed_session


def head_s3_object(s3_client, target):
    bucket = target
    key = None

    if bucket.startswith("s3://"):
        bucket = bucket[5:]

    target_parts = bucket.split("/")
    if len(target_parts) > 1:
        bucket = target_parts[0]
        key = "/".join(target_parts[1:])

    if key:
        s3_client.head_object(Bucket=bucket, Key=key)
        return True
    else:
        s3_client.head_bucket(Bucket=bucket)
        return True


def invoke_lambda_url(session, target_url, region):
    sigv4 = SigV4Auth(session.get_credentials(), 'lambda', region)
    request = AWSRequest(method='GET', url=target_url)
    sigv4.add_auth(request)
    prepped = request.prepare()
    
    return requests.get(target_url, headers=prepped.headers).ok
    

def invoke_apigateway_url(session, target_url, region):
    # TODO: Support API keys
    # TODO: Support different HTTP methods
    sigv4 = SigV4Auth(session.get_credentials(), 'execute-api', region)
    request = AWSRequest(method='POST', url=target_url)
    sigv4.add_auth(request)
    prepped = request.prepare()
    
    return requests.post(target_url, headers=prepped.headers).ok


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--profile", help="AWS CLI profile to execute with", type=str, required=False)
    parser.add_argument("--role", help="ARN of the role to assume", type=str, required=True)
    parser.add_argument("--target", help="ARN or identifier of the target resource", type=str, required=True)
    parser.add_argument("--condition", help="AWS API to call", type=str, required=True, 
                        choices=SUPPORTED_CONDITIONS)
    parser.add_argument("--action", help="Condition context key to test with", type=str, required=True, 
                        choices=SUPPORTED_ACTIONS)
    parser.add_argument("--alphabet", help="String of all characters to test", type=str, required=False, default='0123456789')
    parser.add_argument("--region", help="AWS region to perform action in", type=str, required=False)
    parser.add_argument("--tag-key", help="Tag key when using aws:ResourceTag condition", type=str, required=False)
    args = parser.parse_args()

    if args.condition == 'aws:ResourceTag' and not args.tag_key:
        print("Tag key required when using aws:ResourceTag condition")
        exit(1)

    main(args)

