#!/usr/bin/env python
"""AWSConfig troposphere blueprint."""
from __future__ import print_function
from os.path import dirname, realpath
import sys
import os
import yaml
import hashlib

from stacker.blueprints.base import Blueprint
from stacker.blueprints.variables.types import CFNString, CFNNumber

from troposphere.events import Rule, Target, InputTransformer, EventBusPolicy


from troposphere import (
    Ref, Equals, Not, If,
    FindInMap, GetAtt, Join, Tags, Output
)

from troposphere.sqs import RedrivePolicy, Queue, QueuePolicy

from troposphere.iam import Role, Policy

from troposphere.sns import Subscription, Topic, TopicPolicy

from troposphere.dynamodb import (
    AttributeDefinition, Table, KeySchema, ProvisionedThroughput, SSESpecification,
    TimeToLiveSpecification
)

from troposphere.awslambda import (
    Code, Environment, Function, Permission)

from troposphere.cloudformation import (
    AWSCustomObject
)

from troposphere.ssm import Parameter

import awacs.s3
import awacs.awslambda
import awacs.logs
import awacs.sqs
import awacs.sns
import awacs.sts
import awacs.iam
import awacs.support
from awacs.ssm import GetParameter, GetParameters, PutParameter
from awacs.aws import Allow, Principal, PolicyDocument, Statement
from awacs.sqs import SendMessage
from awacs.logs import CreateLogGroup, CreateLogStream, PutLogEvents
from awacs.sqs import DeleteMessage, ReceiveMessage
from awacs.dynamodb import GetItem, PutItem
from awacs.sns import Publish
from awacs.events import PutPermission, RemovePermission


class CustomUUID(AWSCustomObject):
    resource_type = 'Custom::UUID'

    props = {
        'ServiceToken': (str, True)
    }


class CustomEstablishTrust(AWSCustomObject):
    resource_type = 'Custom::CrossAccntTrust'

    props = {
        'ServiceToken': (str, True),
        'SUB_ACCOUNTS': (str, True)
    }


class CustomSSMParameter(AWSCustomObject):
    resource_type = 'Custom::SSMParameter'

    props = {
        'ServiceToken': (str, True),
        'SLACK_HOOK_KEY': (str, True),
        'SLACK_CHANNEL_KEY': (str, True)
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


class LimitMonitor(Blueprint):
    """Blueprint to deploy AWS Limit Monitor."""

    VARIABLES = {

        'SERVICES': {
            'type': CFNString,
            'description': 'The list of AWS services to trigger events on.'

        },

        'SNSEmail': {
            'type': CFNString,
            'description': '(Required) The email address to subscribe for alert messages.'
        },

        'AccountList': {
            'type': CFNString,
            'default': '',
            'description': 'List of comma-separated and double-quoted account numbers to monitor. '
                           'If you leave this parameter blank, the solution will only monitor limits '
                           'in the primary account. If you enter multiple secondary account IDs, '
                           'you must also provide the primary account ID in this parameter.',
        },

        'SNSEvents': {
            'type': CFNString,
            'default': '',
            'description': 'List of alert levels to send email alerts in response to. '
                           'Leave blank if you do not wish to receive email notifications. '
                           'Must be double-quoted and comma separated.'
        },

        'SlackEvents': {
            'type': CFNString,
            'default': '',
            'description': 'List of alert levels to send Slack alerts in response to. '
                           'Leave blank if you do not wish to receive Slack notifications. '
                           'Must be double-quoted and comma separated.'
        },

        'SlackHookURL': {
            'type': CFNString,
            'default': '',
            'description':  'SSM parameter key for incoming Slack web hook URL. '
                            'Leave blank if you do not wish to receive Slack notifications.'
        },

        'SlackChannel': {
            'type': CFNString,
            'default': '',
            'description': 'SSM parameter key for the Slack channel. '
                           'Leave blank if you do not wish to receive Slack notifications.'
        },

        'ReadUnits': {
            'type': CFNNumber,
            'description': 'The amount of read units required.'
        },

        'WriteUnits': {
            'type': CFNNumber,
            'description': 'The amount of ddb write units required.'
        },

        'SSMParameterChannel': {
            'type': CFNString,
            'description': 'The SSM Parameter Channel Key Name'
        },

        'SSMParameterHookUrl': {
            'type': CFNString,
            'description': 'The SSM Parameter Hook URL Key Name'
        }

    }

    def add_resources(self):
        """Create Resources to deploy Limit Monitor."""
        template = self.template
        variables = self.get_variables()

        path = os.path.dirname(os.path.abspath(path=__file__))
        stacker_dict = yaml.safe_load(open(path + '/' + '../01_limit_monitor_us-east-1.yaml'))

        service_item = ''
        for item in stacker_dict['stacks']['servicelimitmonitor']['variables']['SERVICES']:
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

        """Adding Condition for SingleAccnt."""
        single_accnt = template.add_condition('SingleAccnt', Equals(str(variables['AccountList'].value), ''))

        """Adding Condition for SNSTrue."""
        template.add_condition('SNSTrue', Not(Equals(str(variables['SNSEvents'].value), '')))

        """Adding Condition for SlackTrue."""
        template.add_condition('SlackTrue', Not(Equals(str(variables['SlackEvents'].value), '')))

        """Adding Condition for AnonymousMetric."""
        template.add_condition('AnonymousMetric', Equals(
            FindInMap('MetricsMap', 'Send-Data', 'SendAnonymousData'), 'Yes'))

        """Create the Dead Letter Queue."""

        dead_letter_queue = template.add_resource(Queue(
            'DeadLetterQueue',
            MessageRetentionPeriod='604800'  # 7 day retention
        ))

        """Create Resource for the SQS"""

        event_queue = template.add_resource(Queue(
            'EventQueue',
            RedrivePolicy=RedrivePolicy(
                deadLetterTargetArn=GetAtt(dead_letter_queue, 'Arn'),
                maxReceiveCount='3'
            ),
            VisibilityTimeout='60',
            MessageRetentionPeriod='86400',  # 1 day retention
            DependsOn=[
                dead_letter_queue
            ]
        ))

        """Target for tasqs_rule."""
        tasqs_target = Target(
            'TaSqsTarget',
            Arn=GetAtt(event_queue, 'Arn'),
            Id='LimitMonitorSQSTarget',
        )

        """Limit Monitor Cloudwatch Rules."""
        template.add_resource(Rule(
            'TASQSRule',
            Description='Limit Monitor Solution - Rule for TA SQS events',
            EventPattern={
                'detail': {
                    'check-item-detail': {
                        'Service': variables['SERVICES'].value
                    },
                    'status': [
                        "OK", "WARN", "ERROR"
                    ]
                },
                'detail-type': [
                    'Trusted Advisor Check Item Refresh Notification'
                ],
                'source': [
                    'aws.trustedadvisor'
                ],
                'account':
                    If(
                        single_accnt,
                        Join('', ['"', Ref('AWS::AccountId'), '"']),
                        variables['AccountList'].value
                    )
            },
            State='ENABLED',
            Targets=[
                tasqs_target,
            ],
            DependsOn=[
                event_queue
            ]
        ))

        if variables['SNSEvents'].value != '':

            """Create the SNS Topic Resource"""

            sns_topic = template.add_resource(Topic(
                'SNSTopic',
                Condition='SNSTrue',
                Subscription=[Subscription(
                    Protocol='email',
                    Endpoint=variables['SNSEmail'].ref
                )]
            ))

            """Create the SNS Topic Policy."""

            template.add_resource(TopicPolicy(
                'SNSTopicPolicy',
                PolicyDocument=PolicyDocument(
                    Version='2012-10-17',
                    Statement=[
                        Statement(
                            Effect=Allow,
                            Principal=Principal(
                                'Service',
                                ['events.amazonaws.com']
                            ),
                            Action=[
                                Publish
                            ],
                            Resource=[
                                '*'
                            ]
                        )
                    ]
                ),
                Topics=[
                    Ref(sns_topic)
                ]

            ))

            """Define the tasns_target."""
            tasns_target = Target(
                'TaSnsTarget',
                Arn=Ref(sns_topic),
                Id='LimitMonitorSNSTarget',
                InputTransformer=InputTransformer(
                    InputPathsMap={
                        "limitdetails": "$.detail.check-item-detail",
                        "time": "$.time",
                        "account": "$.account"
                    },
                    InputTemplate='"AWS-Account : <account> || Timestamp : <time> || Limit-Details : <limitdetails>"'
                ),
            )

            """Resource for tasns rule"""
            template.add_resource(Rule(
                'TASNSRule',
                Condition='SNSTrue',
                Description='Limit Monitor Solution - Rule for TA SNS events',
                EventPattern={
                    'detail': {
                        'check-item-detail': {
                            'Service': variables['SERVICES'].value
                            },
                        'status': variables['SNSEvents'].value
                        },
                    'detail-type': [
                        'Trusted Advisor Check Item Refresh Notification'
                    ],
                    'source': [
                        'aws.trustedadvisor'
                    ],
                    'account':
                        If(
                            single_accnt,
                            Join('', ['"', Ref('AWS::AccountId'), '"']),
                            variables['AccountList'].value
                        )
                },
                State='ENABLED',
                Targets=[
                    tasns_target
                ],
                DependsOn=[
                    sns_topic
                ]
            ))

        s3_bucket = FindInMap('SourceCode', 'General', 'S3Bucket')
        s3_key = FindInMap('SourceCode', 'General', 'KeyPrefix')

        """Create the Event Queue Policy."""

        template.add_resource(QueuePolicy(
            'EventQueuePolicy',
            PolicyDocument=PolicyDocument(
                Version='2012-10-17',
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[
                            SendMessage
                        ],
                        Principal=Principal(
                            'Service',
                            ['events.amazonaws.com']
                        ),
                        Resource=[
                            GetAtt(event_queue, 'Arn')
                        ]
                    )
                ]
            ),
            Queues=[
                Ref(event_queue)
            ],
            DependsOn=[
                event_queue
            ]

        ))

        """Create DynamoDb Table Resource."""

        summary_ddb = template.add_resource(Table(
            'SummaryDDB',
            DeletionPolicy='Delete',
            TableName=Join('-', [Ref('AWS::StackName'), 'LimitMonitor']),
            SSESpecification=SSESpecification(
                SSEEnabled=True
            ),
            AttributeDefinitions=[
                AttributeDefinition(
                    AttributeName='MessageId',
                    AttributeType='S'
                ),
                AttributeDefinition(
                    AttributeName='TimeStamp',
                    AttributeType='S'
                )
            ],
            KeySchema=[
                KeySchema(
                    AttributeName='MessageId',
                    KeyType='HASH'
                ),
                KeySchema(
                    AttributeName='TimeStamp',
                    KeyType='RANGE'
                )
            ],
            ProvisionedThroughput=ProvisionedThroughput(
                ReadCapacityUnits=int(variables['ReadUnits'].value),
                WriteCapacityUnits=int(variables['WriteUnits'].value)
            ),
            Tags=Tags(
                Solution='Serverless-Limit-Monitor'
            ),
            TimeToLiveSpecification=TimeToLiveSpecification(
                AttributeName='ExpiryTime',
                Enabled=True
            )
        ))

        """Create the Limit Summarizer Role."""

        limit_summarizer_role = template.add_resource(Role(
            'LimitSummarizerRole',
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
                                    DeleteMessage,
                                    ReceiveMessage
                                ],
                                Resource=[
                                    GetAtt(event_queue, 'Arn')
                                ]
                            ),
                            Statement(
                                Effect=Allow,
                                Action=[
                                    GetItem,
                                    PutItem
                                ],
                                Resource=[
                                    Join(':', ['arn:aws:dynamodb', Ref('AWS::Region'), Ref('AWS::AccountId'),
                                               Join('', ['table/', Ref(summary_ddb)])
                                               ]
                                         )
                                ]
                            )
                        ]
                    ),
                    PolicyName=Join('-', ['Limit-Monitor-Policy', Ref('AWS::StackName'), Ref('AWS::Region')])
                )
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
                    'LOG_LEVEL': 'DEBUG'
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

        if variables['SlackEvents'].value != '':

            """Create SSM Parameter for Slack Channel."""

            template.add_resource(Parameter(
                'SlackChannelName',
                Description='The SSM Parameter Store Key for the Slack Channel Name.',
                Name=variables['SSMParameterChannel'].ref,
                Type='String',
                Value=str(variables['SlackChannel'].value),
            ))

            """Create SSM Parameter for Slack Hook URL."""

            template.add_resource(Parameter(
                'SlackHookUrlLink',
                Description='The SSM Parameter Store Key for the Slack Hook URL.',
                Name=variables['SSMParameterHookUrl'].ref,
                Type='String',
                Value=str(variables['SlackHookURL'].value),
            ))

            """Create the IAM Role for the Slack Notifier Lambda Function."""

            slack_notifier_role = template.add_resource(Role(
                'SlackNotifierRole',
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
                                        GetParameter
                                    ],
                                    Resource=[
                                        Join(':', ['arn:aws:ssm', Ref('AWS::Region'), Ref('AWS::AccountId'), '*']),
                                        Join(':', ['arn:aws:ssm', Ref('AWS::Region'), Ref('AWS::AccountId'), '*'])
                                    ]
                                )
                            ]
                        ),
                        PolicyName=Join('-', ['Limit-Monitor-Policy', Ref('AWS::StackName'), Ref('AWS::Region')])
                    )
                ]
            ))

            """Create the slack Notifier Lambda Function."""

            slack_notifier = template.add_resource(Function(
                'SlackNotifier',
                Description='Serverless Limit Monitor - Lambda function to send notifications on slack',
                Environment=Environment(
                    Variables={
                        'SLACK_HOOK': 'limit_monitor_slack_hook_url',
                        'SLACK_CHANNEL': 'limit_monitor_slack_channel',
                        'LOG_LEVEL': 'DEBUG'
                    }
                ),
                Handler='index.handler',
                Role=GetAtt(slack_notifier_role, 'Arn'),
                Code=Code(
                    S3Bucket=Join('-', [s3_bucket, Ref('AWS::Region')]),
                    S3Key=Join('/', [s3_key, 'limtr-slack-service.zip'])
                ),
                Runtime='nodejs8.10',
                Timeout=300,
                DependsOn=[
                    slack_notifier_role
                ]
            ))

            """Define the taslack Target"""

            taslack_target = Target(
                'TaSlackTarget',
                Arn=GetAtt(slack_notifier, 'Arn'),
                Id='LimitMonitorSlackTarget',
            )

            """Resource for taslack rule."""
            taslack_rule = template.add_resource(Rule(
                'TASlackRule',
                Description='Limit Monitor Solution - Rule for TA Slack events',
                EventPattern={
                    'detail': {
                        'check-item-detail': {
                            'Service': variables['SERVICES'].value
                            },
                        'status': variables['SlackEvents'].value
                        },
                    'detail-type': [
                        'Trusted Advisor Check Item Refresh Notification'
                    ],
                    'source': [
                        'aws.trustedadvisor'
                    ],
                    'account':
                        If(
                            single_accnt,
                            Join('', ['"', Ref('AWS::AccountId'), '"']),
                            variables['AccountList'].value
                        )
                },
                State='ENABLED',
                Targets=[
                    taslack_target
                ],
                DependsOn=[
                    slack_notifier
                ]
            ))

            """Create the Slack Notifier Invoke Lambda Permissions."""

            template.add_resource(Permission(
                'SlackNotifierInvokePermission',
                FunctionName=Ref(slack_notifier),
                Action='lambda:InvokeFunction',
                Principal='events.amazonaws.com',
                SourceArn=GetAtt(taslack_rule, 'Arn'),
                DependsOn=[
                    taslack_rule
                ]
            ))

            # """Create the Custom Resource SSMParameter."""
            #
            # template.add_resource(CustomSSMParameter(
            #     'SSMParameter',
            #     ServiceToken=GetAtt(limtr_helper, 'Arn'),
            #     SLACK_HOOK_KEY=variables['SlackHookURL'].value,
            #     SLACK_CHANNEL_KEY=variables['SlackChannel'].value
            # ))

            """Output for SSM Parameter SlackChannel Key."""

            template.add_output(Output(
                'SlackChannelKey',
                Description='SSM parameter for Slack Channel, change the value for your slack workspace',
                Value=variables['SSMParameterChannel'].value
            ))

            """Output for SSM Parameter SlackHook Key."""

            template.add_output(Output(
                'SlackHookKey',
                Description='SSM parameter for Slack Web Hook, change the value for your slack workspace',
                Value=variables['SSMParameterHookUrl'].value
            ))

        """Create the Custom Resource UUID."""

        create_uuid = template.add_resource(CustomUUID(
            'CreateUUID',
            ServiceToken=GetAtt(limtr_helper, 'Arn')
        ))

        """Create the Lambda Function for the Limit Summarizer."""

        limit_summarizer = template.add_resource(Function(
            'LimitSummarizer',
            Description='Serverless Limit Monitor - Lambda function to summarize service limit usage',
            Environment=Environment(
                Variables={
                    'LIMIT_REPORT_TBL': Ref(summary_ddb),
                    'SQS_URL': Ref(event_queue),
                    'MAX_MESSAGES': 10,
                    'MAX_LOOPS': 10,
                    'ANONYMOUS_DATA': FindInMap('MetricsMap', 'Send-Data', 'SendAnonymousData'),
                    'SOLUTION': 'SO0005',
                    'UUID': Ref(create_uuid),
                    'LOG_LEVEL': 'DEBUG'
                }
            ),
            Handler='index.handler',
            Role=GetAtt(limit_summarizer_role, 'Arn'),
            Code=Code(
                S3Bucket=Join('-', [s3_bucket, Ref('AWS::Region')]),
                S3Key=Join('/', [s3_key, 'limtr-report-service.zip'])
            ),
            Runtime='nodejs8.10',
            Timeout=300
        ))

        """Create the target for queue poll schedule."""

        queue_poll_target = Target(
            'QueuePollTarget',
            Arn=GetAtt(limit_summarizer, 'Arn'),
            Id='SqsPollRate'
        )

        """Create the resource for queue poll schedule."""

        queue_poll_schedule = template.add_resource(Rule(
            'QueuePollSchedule',
            Description='Limit Monitor Solution - Schedule to poll SQS queue',
            ScheduleExpression='rate(1 day)',
            State='ENABLED',
            Targets=[
                queue_poll_target
            ]
        ))

        """Create Lambda Permission for Limit Summarizer."""

        template.add_resource(Permission(
            'SummarizerInvokePermission',
            Action='lambda:InvokeFunction',
            FunctionName=Ref(limit_summarizer),
            Principal='events.amazonaws.com',
            SourceArn=GetAtt(queue_poll_schedule, 'Arn'),
            DependsOn=[
                queue_poll_schedule
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
                    'AWS_SERVICES': str(service_item[:-1]),
                    'LOG_LEVEL': 'DEBUG'
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

        """Create the Custom Resource EstablishTrust"""

        template.add_resource(CustomEstablishTrust(
            'EstablishTrust',
            ServiceToken=GetAtt(limtr_helper, 'Arn'),
            SUB_ACCOUNTS=str(variables['AccountList'].value)
        ))

        """Create the Custom Resource AccountAnonymousData."""

        template.add_resource(CustomAccountAnonymousData(
            'AccountAnonymousData',
            ServiceToken=GetAtt(limtr_helper, 'Arn'),
            SOLUTION='SO0005',
            UUID=Ref(create_uuid),
            SNS_EVENTS=If('SNSTrue', 'true', 'false'),
            SLACK_EVENTS=If('SlackTrue', 'true', 'false'),
            SUB_ACCOUNTS=str(variables['AccountList'].value),
            VERSION='v5.1.1',
            TA_REFRESH_RATE=FindInMap('RefreshRate', 'CronSchedule', 'Default')
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

        """Create the Event Bus Policy."""

        for account in stacker_dict['stacks']['servicelimitmonitor']['variables']['AccountList']:
            uuid = hashlib.md5(account.encode('utf')).hexdigest()
            template.add_resource(EventBusPolicy(
                'EventBus' + uuid,
                Action='events:PutEvents',
                Principal=(str(account)),
                StatementId=('MyStatement' + '_' + str(uuid))
            ))

        """Output for Service Checks."""

        template.add_output(Output(
            'ServiceChecks',
            Description='Service limits monitored in the account',
            Value=str(service_item[:-1])
        ))

        """Output for AccountList."""

        template.add_output(Output(
            'AccountList',
            Description='Accounts to be monitored for service limits',
            Value=str(variables['AccountList'].value)
        ))

    def create_template(self):
        """Create template (main function called by Stacker)."""
        self.template.add_version('2010-09-09')
        self.template.add_description("Limit-Monitor Stack "
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

    print(LimitMonitor('test', Context({'namespace': 'test'}), None).to_json())
