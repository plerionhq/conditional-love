# Conditional Love

An AWS metadata enumeration tool by [Daniel Grzelak](https://www.linkedin.com/in/danielgrzelak/) of [Plerion](https://plerion). Use it to enumerate resource tags, account IDs, org IDs etc.

Inspired by [S3 Account Search](https://github.com/WeAreCloudar/s3-account-search) by [Cloudar](https://cloudar.be/).

## Description

During the dark times of 2021 [Ben Bridts](https://twitter.com/benbridts) published a [smashing blog post](https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/) titled "Finding the Account ID of any public S3 bucket name". 

In his blog post Ben pointed out that the condition key "S3:ResourceAccount" could be used to enumerate account IDs one character at a time by using the "StringLike" operator and including a wild card. For example, if you want to know if the first 2 digits of an account ID are "43", you would use this in a caller policy:

```
"Condition": {
    "StringLike": {"s3:ResourceAccount": ["43*"]}
}
```

There are now a number of global resource condition keys for use in policy evaluation. There are also many other services that allow cross-account resource sharing with identifiers that don't include account IDs. We extended Ben's work with the following findings:

* Finding 1: The account ID enumeration technique with global condition "aws:ResourceAccount" can be applied to almost all other services and resources.
* Finding 2: There are other global resource condition keys that can be similarly abused for enumeration of other metadata such as organisation IDs and resource tags.

Conditional Love is a Python tool that allows the user to execute these techniques against an AWS target.

A more complete discussion of the tool and technique has been published on the [Plerion Blog](https://blog.plerion.com/conditional-love-for-aws-metadata-enumeration/)

## Usage

```
usage: conditional-love.py [-h] [--profile PROFILE] --role ROLE --target TARGET 
                           --condition {s3:ResourceAccount,aws:ResourceAccount,aws:ResourceOrgPaths,aws:ResourceOrgID,aws:ResourceTag,lambda:FunctionArn} 
                           --action {s3:HeadObject,dataexchange:GetDataSet,lambda:InvokeFunctionUrl,execute-api:Invoke,sts:AssumeRole,sqs:ReceiveMessage} 
                           [--alphabet ALPHABET] [--region REGION] [--tag-key TAG_KEY]

options:
  -h, --help            show this help message and exit
  --profile PROFILE     AWS CLI profile to execute with
  --role ROLE           ARN of the role to assume
  --target TARGET       ARN or identifier of the target resource
  --condition {s3:ResourceAccount,aws:ResourceAccount,aws:ResourceOrgPaths,aws:ResourceOrgID,aws:ResourceTag,lambda:FunctionArn}
                        AWS API to call
  --action {s3:HeadObject,dataexchange:GetDataSet,lambda:InvokeFunctionUrl,execute-api:Invoke,sts:AssumeRole,sqs:ReceiveMessage}
                        Condition context key to test with
  --alphabet ALPHABET   String of all characters to test
  --region REGION       AWS region to perform action in
  --tag-key TAG_KEY     Tag key when using aws:ResourceTag condition
```

### Installation

```
pip install -r requirements.txt
```

### Prerequisites

1. Python3 with requirements installed
2. AWS CLI installed with credentials configured or a profile setup
3. A IAM role you can assume with permissions to perform the API actions you want to test

### Examples

Identify the Organisation ID the 'Commoncrawl' S3 bucket belongs to:
```
% ./conditional-love.py --profile=<YOUR_CLI_PROFILE> \
                        --role=<YOUR_ROLE_ARN_TO_ASSUME> \
                        --action=s3:HeadObject \
                        --condition=aws:ResourceOrgID \
                        --target=s3://commoncrawl/ \
                        --alphabet=abcdefghijklmnopqrstuvwxyz-
Starting to be wrong. Please be patient...
=> o
=> o-
=> o-f
=> o-fz
=> o-fz?
=> o-fz??
=> o-fz???
=> o-fz????
=> o-fz?????
=> o-fz?????o
=> o-fz?????ot
```

Identify the account ID that the Carvana 'Car Sales for United States' DataExchange dataset belongs to:
```
$ ./conditional-love.py --profile=<YOUR_CLI_PROFILE> \
                        --role=<YOUR_ROLE_ARN_TO_ASSUME> \
                        --action=dataexchange:GetDataSet \
                        --condition=aws:ResourceAccount \
                        --target=935c01c3a7f5e3499df7dff4dedeebae \
                        --region=us-west-2
Starting to be wrong. Please be patient...
=> 1
=> 10
=> 102
=> 102?
=> 102??
=> 102???
=> 102????
=> 102?????
=> 102??????
=> 102??????7
=> 102??????70
=> 102??????709
```

Identify the value of the OwnerEmail tag of a role you can assume:
```
% ./conditional-love.py --profile=<YOUR_CLI_PROFILE> \
                        --role=<YOUR_ROLE_ARN_TO_ASSUME> \
                        --action=sts:AssumeRole \
                        --condition=aws:ResourceTag \
                        --tag-key=OwnerEmail \
                        --target=<TARGET_ROLE_ARN> \
                        --alphabet=abcdefghijklmnopqrstuvwxyz.@
Starting to be wrong. Please be patient...
=> d
=> da
=> dag
=> dagr
=> dagrz
=> dagrz@
=> dagrz@p
=> dagrz@pl
=> dagrz@ple
=> dagrz@pler
=> dagrz@pleri
=> dagrz@plerio
=> dagrz@plerion
=> dagrz@plerion.
=> dagrz@plerion.c
=> dagrz@plerion.co
=> dagrz@plerion.com
```

## Extending conditional love

### Adding conditions

To add a new policy condition, add an item to the `SUPPORTED_CONDITIONS` list at the top of `conditional-love.py`. That's it.

A full list of global conditions is documented [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html) and service specific conditions [here](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html). 

### Adding actions

Adding actions is a little bit more involved than conditions:

1. Add an item to the `SUPPORTED_ACTIONS` list at the top of `conditional-love.py`.
2. Locate the cascading action if statement inside the `can_access_target_with_policy` function and use the boto `client` to make the API call you want.

More work may be required for API calls that are less standard. For example, invoking Lambda functionl URLs and API Gateways requires authentication headers to be built manually.

## Troubleshooting

* Watch out for missed permissions on the role you pass in to assume. If you are testing or adding a new action, make sure that role has permissions to execute that action.
* Some target resources are region sensitive, so make sure you are passing in the right region if in doubt.
* Target API Gateways and Lambda URLs must have their authentication type set to `AWS_IAM` in order to be processed by the policy engine.
* The default alphabet is just digits 0-9 so if you are enumerating something with other chatacters, make sure to pass your alphabet in.

## License

Distributed under the MIT License. See LICENSE.txt for more information.

## Contact

Want to discuss Conditional Love? Get in touch on [Twitter](https://twitter.com/PlerionHQ) or [LinkedIn](https://linkedin.com/company/plerion).
