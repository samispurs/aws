#!/usr/bin/env python
"""AWSConfig troposphere blueprint."""
from __future__ import print_function
from os.path import dirname, realpath
import sys
import os
import yaml

from stacker.blueprints.base import Blueprint
from stacker.blueprints.variables.types import CFNString

from troposphere.events import Rule, Target

from troposphere import (
    Ref, FindInMap, GetAtt, Join, Output
)

from troposphere.iam import Role, Policy

from troposphere.awslambda import (
    Code, Environment, Function, Permission)

from troposphere.cloudformation import (
    AWSCustomObject
)

import awacs.s3
import awacs.awslambda
import awacs.logs
import awacs.sqs
import awacs.sns
import awacs.sts
import awacs.iam
import awacs.support
from awacs.ssm import GetParameters, PutParameter
from awacs.aws import Allow, Principal, PolicyDocument, Statement
from awacs.logs import CreateLogGroup, CreateLogStream, PutLogEvents
from awacs.events import PutPermission, RemovePermission


class CustomUUID(AWSCustomObject):
    resource_type = 'Custom::UUID'

    props = {
        'ServiceToken': (str, True)
    }


class CustomAccountAnonymousData(AWSCustomObject):
    resource_type = 'Custom::AccountAnonymousData'

    props = {
        'ServiceToken': (str, True),
        'UUID': (str, True),
        'SNS_EVENTS': (str, True),
        'SLACK_EVENTS': (str, True),
        'SUB_ACCOUNTS': (str, True),
        'VERSION': (str, True),
        'TA_REFRESH_RATE': (str, True)
    }


class CustomDeploymentData(AWSCustomObject):
    resource_type = 'Custom::DeploymentData'

    props = {
        'ServiceToken': (str, True),
        'SOLUTION': (str, True),
        'UUID': (str, True),
        'VERSION': (str, True),
        'ANONYMOUS_DATA': (str, True)
    }


class LimitMonitorSpoke(Blueprint):
    """Blueprint to deploy AWS Limit Monitor."""

    VARIABLES = {

        'SERVICES': {
            'type': CFNString,
            'description': 'The list of AWS services to trigger events on.'

        },

        'MasterAccount': {
            'type': CFNString,
            'default': '',
            'description': 'List of comma-separated and double-quoted account numbers to monitor. '
                           'If you leave this parameter blank, the solution will only monitor limits '
                           'in the primary account. If you enter multiple secondary account IDs, '
                           'you must also provide the primary account ID in this parameter.',
        },

    }

    def add_resources(self):
        """Create Resources to deploy Limit Monitor."""
        template = self.template
        variables = self.get_variables()

        path = os.path.dirname(os.path.abspath(path=__file__))
        stacker_dict = yaml.safe_load(open(path + '/' + '../01_limit_monitor_spoke_us-east-1.yaml'))

        service_item = ''
        for item in stacker_dict['stacks']['servicelimitmonitorspoke']['variables']['SERVICES']:
            quoted_item = '"' + item + '"'
            service_item = service_item + quoted_item + ','

        """Adding Mapping for AnonymousData"""
        template.add_mapping(
            'MetricsMap', {
                'Send-Data': {
                    'SendAnonymousData': 'Yes'
                }
            }
        )

        """Adding Mapping for RefreshRate."""
        template.add_mapping(
            'RefreshRate', {
                'CronSchedule': {
                    'Default': 'rate(1 day)'
                }
            }
        )

        """Adding Mapping for SourceCode."""
        template.add_mapping(
            'SourceCode', {
                'General': {
                    'S3Bucket': 'solutions',
                    'KeyPrefix': 'limit-monitor/v5.1.1'
                }
            }
        )

        # """Adding Mapping for EventsMap."""
        # template.add_mapping(
        #     'EventsMap', {
        #         'Checks': {
        #             'Services': '"AutoScaling","CloudFormation","EBS","EC2","ELB","IAM","RDS","VPC"'
        #
        #         }
        #     }
        # )

        s3_bucket = FindInMap('SourceCode', 'General', 'S3Bucket')
        s3_key = FindInMap('SourceCode', 'General', 'KeyPrefix')

        """TAOkRule Target Resource Definition."""

        ta_ok_rule_target = Target(
            'TAOkRuleTarget',
            Arn=Join(':', ['arn:aws:events', 'us-east-1', str(variables['MasterAccount'].value), 'event-bus/default']),
            Id='SpokeOkTarget',
        )

        """CWR - Rule for TA OK events'."""
        template.add_resource(Rule(
            'TAOkRule',
            Description='Limit Monitor Solution - Spoke - Rule for TA OK events',
            EventPattern={
                'account': [
                    Ref('AWS::AccountId')
                ],
                'source': [
                    'aws.trustedadvisor'
                ],
                'detail-type': [
                    'Trusted Advisor Check Item Refresh Notification'
                ],
                'detail': {
                    'status': [
                        "OK"
                    ],
                    'check-item-detail': {
                        'Service': variables['SERVICES'].value
                    }
                }
            },
            State='ENABLED',
            Targets=[
                ta_ok_rule_target,
            ]
        ))

        """TAWarnRule Target Resource Definition."""

        ta_warn_rule_target = Target(
            'TAWarnRuleTarget',
            Arn=Join(':', ['arn:aws:events', 'us-east-1', str(variables['MasterAccount'].value), 'event-bus/default']),
            Id='SpokeWarnTarget',
        )

        """CWR - Rule for TA WARN events'"""
        template.add_resource(Rule(
            'TAWarnRule',
            Description='Limit Monitor Solution - Spoke - Rule for TA WARN events',
            EventPattern={
                'account': [
                    Ref('AWS::AccountId')
                ],
                'source': [
                    'aws.trustedadvisor'
                ],
                'detail-type': [
                    'Trusted Advisor Check Item Refresh Notification'
                ],
                'detail': {
                    'status': [
                        "WARN"
                    ],
                    'check-item-detail': {
                        'Service': variables['SERVICES'].value
                    }
                }
            },
            State='ENABLED',
            Targets=[
                ta_warn_rule_target,
            ]
        ))

        """TAErrorRule Target Resource Definition."""

        ta_error_rule_target = Target(
            'TAErrorRuleTarget',
            Arn=Join(':', ['arn:aws:events', 'us-east-1', str(variables['MasterAccount'].value), 'event-bus/default']),
            Id='SpokeErrorTarget',
        )

        """CWR - Rule for TA Error events'"""
        template.add_resource(Rule(
            'TAErrorRule',
            Description='Limit Monitor Solution - Spoke - Rule for TA WARN events',
            EventPattern={
                'account': [
                    Ref('AWS::AccountId')
                ],
                'source': [
                    'aws.trustedadvisor'
                ],
                'detail-type': [
                    'Trusted Advisor Check Item Refresh Notification'
                ],
                'detail': {
                    'status': [
                        "ERROR"
                    ],
                    'check-item-detail': {
                        'Service': variables['SERVICES'].value
                    }
                }
            },
            State='ENABLED',
            Targets=[
                ta_error_rule_target,
            ]
        ))

        """Create the IAM role for the TA Refresher Lambda Function"""

        ta_refresher_role = template.add_resource(Role(
            'TARefresherRole',
            AssumeRolePolicyDocument=PolicyDocument(
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[
                            awacs.sts.AssumeRole
                        ],
                        Principal=Principal(
                            'Service',
                            ['lambda.amazonaws.com']
                        )
                    )
                ]
            ),
            Path='/',
            Policies=[
                Policy(
                    PolicyDocument=PolicyDocument(
                        Version='2012-10-17',
                        Statement=[
                            Statement(
                                Effect=Allow,
                                Action=[
                                    CreateLogGroup,
                                    CreateLogStream,
                                    PutLogEvents
                                ],
                                Resource=[
                                    Join(':', ['arn:aws:logs', Ref('AWS::Region'), Ref('AWS::AccountId'),
                                               'log-group', '/aws/lambda/*'])
                                ]
                            ),
                            Statement(
                                Effect=Allow,
                                Action=[
                                    awacs.support.Action('*')
                                ],
                                Resource=[
                                    '*'
                                ]
                            ),
                        ]
                    ),
                    PolicyName=Join('-', ['Limit-Monitor-Refresher-Policy', Ref('AWS::StackName')])
                )
            ]
        ))

        """Create TA Refresher Lambda Function."""

        ta_refresher = template.add_resource(Function(
            'TARefresher',
            Description='Serverless Limit Monitor - Lambda function to summarize service limits',
            Environment=Environment(
                Variables={
                    # 'AWS_SERVICES': FindInMap('EventsMap', 'Checks', 'Services'),
                    'AWS_SERVICES': str(service_item[:-1]),
                    'LOG_LEVEL': 'ERROR'
                }
            ),
            Handler='index.handler',
            Role=GetAtt(ta_refresher_role, 'Arn'),
            Code=Code(
                S3Bucket=Join('-', [s3_bucket, Ref('AWS::Region')]),
                S3Key=Join('/', [s3_key, 'limtr-refresh-service.zip'])
            ),
            Runtime='nodejs8.10',
            Timeout=300,
            DependsOn=[
                ta_refresher_role
            ]
        ))

        """Create the target for Refresh Schedule."""

        ta_refresher_target = Target(
            'TARefreshRate',
            Arn=GetAtt(ta_refresher, 'Arn'),
            Id='SqsPollRate'
        )

        """Create the TARefreshSchedule Rule."""

        ta_refresh_schedule = template.add_resource(Rule(
            'TARefreshSchedule',
            Description='Limit Monitor Solution - Schedule to refresh TA checks',
            ScheduleExpression=FindInMap('RefreshRate', 'CronSchedule', 'Default'),
            State='ENABLED',
            Targets=[
                ta_refresher_target
            ],
            DependsOn=[
                ta_refresher
            ]

        ))

        """Create the Ta Refresher Lambda Permission."""

        template.add_resource(Permission(
            'TARefresherInvokePermission',
            FunctionName=Ref(ta_refresher),
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=GetAtt(ta_refresh_schedule, 'Arn'),
            DependsOn=[
                ta_refresher
            ]
        ))

        """Create the Limtr Helper Role."""

        limtr_helper_role = template.add_resource(Role(
            'LimtrHelperRole',
            AssumeRolePolicyDocument=PolicyDocument(
                Version='2012-10-17',
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[
                            awacs.sts.AssumeRole
                        ],
                        Principal=Principal(
                            'Service',
                            ['lambda.amazonaws.com']
                        )
                    )
                ]
            ),
            Path='/',
            Policies=[
                Policy(
                    PolicyDocument=PolicyDocument(
                        Version='2012-10-17',
                        Statement=[
                            Statement(
                                Effect=Allow,
                                Action=[
                                    CreateLogGroup,
                                    CreateLogStream,
                                    PutLogEvents
                                ],
                                Resource=[
                                    Join(':', ['arn:aws:logs', Ref('AWS::Region'), Ref('AWS::AccountId'),
                                               'log-group', '/aws/lambda/*'])
                                ]
                            ),
                            Statement(
                                Effect=Allow,
                                Action=[
                                    PutPermission,
                                    RemovePermission
                                ],
                                Resource=[
                                    Join(':', ['arn:aws:events', Ref('AWS::Region'), Ref('AWS::AccountId'),
                                               'event-bus/default'])
                                ]
                            ),
                            Statement(
                                Effect=Allow,
                                Action=[
                                    GetParameters,
                                    PutParameter
                                ],
                                Resource=[
                                    Join(':', ['arn:aws:ssm', Ref('AWS::Region'), Ref('AWS::AccountId'),
                                               'parameter/*'])
                                ]
                            )
                        ]
                    ),
                    PolicyName='Custom_Limtr_Helper_Permissions'
                )
            ]
        ))

        """Create the Lambda Function for the Limtr Helper."""

        limtr_helper = template.add_resource(Function(
            'LimtrHelperFunction',
            Description='This function generates UUID, establishes cross account trust '
                        'on CloudWatch Event Bus and sends anonymous metric',
            Handler='index.handler',
            Environment=Environment(
                Variables={
                    'LOG_LEVEL': 'ERROR'
                }
            ),
            Code=Code(
                S3Bucket=Join('-', [s3_bucket, Ref('AWS::Region')]),
                S3Key=Join('/', [s3_key, 'limtr-helper-service.zip'])
            ),
            Role=GetAtt(limtr_helper_role, 'Arn'),
            Runtime='nodejs8.10',
            Timeout=300,
            DependsOn=[
                limtr_helper_role
            ]
        ))

        """Create the Custom Resource UUID."""

        create_uuid = template.add_resource(CustomUUID(
            'CreateUUID',
            ServiceToken=GetAtt(limtr_helper, 'Arn')
        ))

        """Create the Custom Resource DeploymentData."""

        template.add_resource(CustomDeploymentData(
            'DeploymentData',
            ServiceToken=GetAtt(limtr_helper, 'Arn'),
            SOLUTION='SO0005',
            UUID=Ref(create_uuid),
            VERSION='v5.1.1',
            ANONYMOUS_DATA=FindInMap('MetricsMap', 'Send-Data', 'SendAnonymousData')
        ))

        """Output for Service Checks."""

        template.add_output(Output(
            'ServiceChecks',
            Description='Service limits monitored in the account',
            Value=str(service_item[:-1])
        ))

    def create_template(self):
        """Create template (main function called by Stacker)."""
        self.template.add_version('2010-09-09')
        self.template.add_description("Limit-Monitor Stack-Spoke "
                                      "- {0}".format(version()))
        self.add_resources()


def version():
    """Call version function from top of repo."""
    root_dir = dirname(dirname(dirname(dirname(realpath(__file__)))))
    if root_dir not in sys.path:
        sys.path.append(root_dir)
    import platform  # pylint: disable=import-error
    return platform.version()


# Helper section to enable easy blueprint -> template generation
# (just run `python <thisfile>` to output the json)
if __name__ == "__main__":
    from stacker.context import Context

    print(LimitMonitorSpoke('test', Context({'namespace': 'test'}), None).to_json())
