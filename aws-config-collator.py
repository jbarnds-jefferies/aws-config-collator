#!/usr/bin/env python
import botocore.session
from datetime import datetime, tzinfo, timedelta
from argparse import ArgumentParser
import json
import os
import platform
import sys
import hashlib
from collections import defaultdict
import warnings

requiredBotocoreVersion = "1.27.77"
usage = "Usage: python importscript.py --profile <profile_name> --regions <region_name> [... --profile <profile_name> --regions <region_name_1> <region_name_2>] [-c] [-a] [-o <output file>]"

ERRORS = []
COUNT = False
ERROR_COLOR = '\033[91m'
WARNING_COLOR = '\033[93m'
END_COLOR = '\033[0m'

# suppress the warning about endpoint url
# For more details,see https://github.com/boto/botocore/issues/2705
warnings.filterwarnings('ignore', category=FutureWarning, module='botocore.client')

class SimpleUtc(tzinfo):
    def tzname(self):
        return "UTC"

    def utcoffset(self, dt):
        return timedelta(0)

def print_err(msg, warning=False):
    start_color = WARNING_COLOR if warning else ERROR_COLOR
    print(start_color + msg + END_COLOR)

class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.utcnow().replace(tzinfo=SimpleUtc()).isoformat()

        return json.JSONEncoder.default(self, o)


class AwsImportTarget:
    def __init__(self, profile_name, region):
        self.profile_name = profile_name
        self.region = region


def chunk_list(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]

def flatten_list(l):
    return [item for sublist in l for item in sublist]

def encrypt_string(raw_string):
    return hashlib.sha256(raw_string.encode()).hexdigest()

def handle_error(target_info, e, name=''):
    errorMessage = 'Error: {account}:{region}:{name} {errorMessage}'.format(
        account=target_info.profile_name, region=target_info.region, name=name, errorMessage=str(e))
    ERRORS.append(errorMessage)
    print_err(errorMessage)
    if isinstance(e, AttributeError):
        print_err("Attribute error due to imcompatible botocore version. Consider updating your botocoreversion to " + requiredBotocoreVersion)


def make_request(request_fn, target_info, resourceName, key, abort_on_error = False, filters = False):
    try:
        print('Executing {account}:{region}:{resourceName}'.format(
            account=target_info.profile_name, region=target_info.region, resourceName=resourceName))
        result = request_fn(Filters=filters) if filters else request_fn()
        return result.get(key, [])
    except Exception as e:
        handle_error(target_info, e, resourceName)
        if COUNT and abort_on_error:
            print_err('Unable to count resources because of error requesting required resources')
            exit()
        else:
            return []

def get_complete_api_gateways(client, target_info):
    try:
        print('Executing {account}:{region}:apigateway:GET'.format(
            account=target_info.profile_name, region=target_info.region))
        result = client.get_rest_apis().get('items', [])
        for rest_api in result:
            api_id = rest_api['id']
            rest_api_resources = client.get_resources(
                restApiId=api_id, embed=['methods']).get('items')

            def get_integrations_for_resource(resource):
                integrations = []
                methods = resource.get('resourceMethods', {})
                for method in methods:
                    integration = methods[method].get(
                        'methodIntegration', None)
                    if integration:
                        integrations.append(integration)

                return integrations

            from itertools import chain
            integrations = list(chain.from_iterable(map(get_integrations_for_resource, rest_api_resources)))

            resources_obj = {
                'resources': rest_api_resources,
                'integrations': integrations
            }
            rest_api.update(resources_obj)
        return result
    except Exception as e:
        handle_error(target_info, e, 'apigateway:get_rest_apis,get_resources,get_integrations')
        return []

def get_complete_api_gateway_v2s(client, target_info):
    try:
        print('Executing {account}:{region}:apigatewayv2:GET'.format(
            account=target_info.profile_name, region=target_info.region))
        result = client.get_apis().get('Items', [])
        for api in result:
            api_id = api['ApiId']
            api_routes = client.get_routes(ApiId = api_id).get('Items')
            api_integrations = client.get_integrations(ApiId = api_id).get('Items')
            extras_obj = {
                'Routes': api_routes,
                'Integrations': api_integrations
            }
            api.update(extras_obj)
        return result
    except Exception as e:
        handle_error(target_info, e, 'apigatewayv2:get_apis,get_routes,get_integrations')
        return []

def get_cloudfront_distributions(client, target_info):
    try:
        print('Executing {account}:{region}:cloudfront:list_distributions'.format(
            account=target_info.profile_name, region=target_info.region))
        result = client.list_distributions().get(
            'DistributionList', {}).get('Items', [])
        return result
    except Exception as e:
        handle_error(target_info, e, 'cloudfront:list_distributions:')
        return []


def get_lambda_functions(client, target_info):
    try:
        print('Executing {account}:{region}:lambda:list_functions'.format(
            account=target_info.profile_name, region=target_info.region))

        result = client.list_functions()
        functions = result['Functions']
        while 'NextMarker' in result:
            result = client.list_functions(Marker=result['NextMarker'])
            functions.extend(result['Functions'])

        for lambdaFunction in functions:
            if 'Environment' in lambdaFunction:
                del lambdaFunction['Environment']
            try:
                tags = client.list_tags(Resource=lambdaFunction['FunctionArn'])['Tags']
                tagsObj = {
                    'Tags': tags
                }
                lambdaFunction.update(tagsObj)
            except Exception as e:
                print('Error fetching tag info for lambda function "{arn}".\nError: {error}'.format(arn=lambdaFunction['FunctionArn'], error=str(e)))

        return functions
    except Exception as e:
        handle_error(target_info, e, 'lambda:list_functions:')
        if COUNT:
            print_err('Unable to count resources because of error requesting required resources')
            exit()
        else:
            return []

def get_lambda_event_source_mappings(client, target_info):
    try:
        print('Executing {account}:{region}:lambda:list_event_source_mappings'.format(
            account=target_info.profile_name, region=target_info.region))

        result = client.list_event_source_mappings(MaxItems=100)
        mappings = result['EventSourceMappings']
        while 'NextMarker' in result:
            result = client.list_functions(Marker=result['NextMarker'], MaxItems=100)
            mappings.extend(result['EventSourceMappings'])

        return mappings
    except Exception as e:
        handle_error(target_info, e, 'lambda:list_event_source_mappings:')
        if COUNT:
            print_err('Unable to count resources because of error requesting required resources')
            exit()
        else:
            return []

def get_appsync_graphqlapis(client, target_info):
    try:
        print('Executing {account}:{region}:appsync:list_graphql_apis'.format(
            account=target_info.profile_name, region=target_info.region))
        graphql_apis = client.list_graphql_apis()['graphqlApis']
        for graphql_api in graphql_apis:
            try:
                dataSources = client.list_data_sources(apiId=graphql_api['apiId'])['dataSources']
                graphql_api['dataSources'] = dataSources
            except Exception as e:
                print('Error fetching dataSources for AppSync GraphQL API "{arn}"\nError: {error}'.format(arn=graphql_api['arn'], error=str(e)))
        return graphql_apis
    except Exception as e:
        handle_error(target_info, e, 'appsync:list_graphql_apis')
        if COUNT:
            print_err('Unable to count resources because of error requesting required resources')
            exit()
        else:
            return []

def get_sns_subscriptions(client, target_info):
    try:
        print('Executing {account}:{region}:sns:list_subscriptions'.format(
            account=target_info.profile_name, region=target_info.region))
        result = client.list_subscriptions()
        subscriptions = result.get('Subscriptions') if 'Subscriptions' in result else []
        while 'NextToken' in result:
            result = client.list_subscriptions(NextToken=result['NextToken'])
            subscriptions.extend(result.get('Subscriptions') if 'Subscriptions' in result else [])
        return subscriptions

    except Exception as e:
        handle_error(target_info, e, 'sns:list_subscriptions')
        if COUNT:
            print_err('Unable to count resources because of error requesting required resources')
            exit()
        else:
            return []

def list_network_firewalls(client, target_info):
    result = client.list_firewalls()
    firewalls = result.get("Firewalls") if "Firewalls" in result else []

    while "NextToken" in result:
        result = client.list_firewalls(NextToken = result["NextToken"])
        if "Firewalls" in result:
            firewalls.extend(result.get("Firewalls"))

    firewallArns = map(lambda firewall: firewall.get('FirewallArn'), firewalls)
    return list(firewallArns)

def get_network_firewalls(client, target_info):
    try:
        print('Executing {account}:{region}:network-firewalls:list_firewalls'.format(
            account=target_info.profile_name, region=target_info.region))
        firewallArns = list_network_firewalls(client, target_info)
        firewalls = []
        for firewallArn in firewallArns:
            result = client.describe_firewall(FirewallArn=firewallArn)
            metadata = result.get("Firewall", [])
            firewalls.append(metadata)
        return firewalls
    except Exception as e:
        handle_error(target_info, e, 'network-firewalls:list_firewalls:')
        if COUNT:
            print_err('Unable to count resources because of error requesting required resources')
            exit()
        else:
            return []

def get_transit_gateway_attachments(client, target_info, filters):
    try:
        result = client.describe_transit_gateway_attachments(Filters=filters)
        return result['TransitGatewayAttachments']

    except Exception as e:
        handle_error(target_info, e, 'ec2:describe_transit_gateway_attachments')
        return []


def get_transit_gateway_route_tables(client, target_info, filters):
    try:
        result = client.describe_transit_gateway_route_tables(Filters=filters)
        route_filters = {
            'Name': 'state',
            'Values': [
                'active',
            ]
        },
        for route_table in result['TransitGatewayRouteTables']:
            route_table['TransitGatewayRoutes'] = get_transit_gateway_routes(client, target_info, route_filters, route_table['TransitGatewayRouteTableId'])
        return result['TransitGatewayRouteTables']

    except Exception as e:
        handle_error(target_info, e, 'ec2:describe_transit_gateway_route_tables')
        return []


def get_transit_gateway_routes(client, target_info, filters, transit_gateway_route_table_id):
    try:
        result = client.search_transit_gateway_routes(Filters=filters, TransitGatewayRouteTableId=transit_gateway_route_table_id)
        return result['Routes']

    except Exception as e:
        handle_error(target_info, e, 'ec2:search_transit_gateway_routes')
        return []


def get_transit_gateways(client, target_info):
    try:
        transit_gateways = make_request(client.describe_transit_gateways, target_info, 'ec2:describe_transit_gateways', 'TransitGateways')
        for tg in transit_gateways:
            filters = {
                    'Name': 'transit-gateway-id',
                    'Values': [
                        tg['TransitGatewayId'],
                    ]
            },
            tg['TransitGatewayRouteTables'] = get_transit_gateway_route_tables(client, target_info, filters)
            tg['TransitGatewayAttachments'] = get_transit_gateway_attachments(client, target_info, filters)

        return transit_gateways

    except Exception as e:
        handle_error(target_info, e, 'ec2:describe_transit_gateways')
        return []


def get_elb2_target_health(client, target_group_arn, target_info):
    try:
        response = client.describe_target_health(TargetGroupArn=target_group_arn)['TargetHealthDescriptions']
        return response
    except Exception as e:
        handle_error(target_info, e, 'elbv2:describe_target_health:')
        return []

def get_target_groups(client, target_info):
    try:
        target_groups = make_request(client.describe_target_groups, target_info, 'elbv2:describe_target_groups', 'TargetGroups')
        print('Executing {account}:{region}:elbv2:describe_target_health'.format(account=target_info.profile_name, region=target_info.region))
        for target_group in target_groups:
            target_group['TargetHealthDescriptions'] = get_elb2_target_health(client, target_group['TargetGroupArn'], target_info)
        return target_groups

    except Exception as e:
        handle_error(target_info, e, 'elbv2:describe_target_groups')
        return []

snsTopicAttributeWhitelist = {
    "TopicArn",
    "Owner",
    "Policy",
    "DisplayName",
    "SubscriptionsPending",
    "SubscriptionsConfirmed",
    "SubscriptionsDeleted",
    "DeliveryPolicy",
    "EffectiveDeliveryPolicy",
    "KmsMasterKeyId"
}

def get_sns_topics(client, topics, target_info):
    try:
        result = []
        for t in topics:
            attrs = client.get_topic_attributes(TopicArn=t['TopicArn'])
            whitelistedAttributes = {key: value for (key,value) in attrs['Attributes'].items() if key in snsTopicAttributeWhitelist}
            result.append({
                'Attributes': whitelistedAttributes,
                'TopicArn': t['TopicArn'],
            })
        return result
    except Exception as e:
        handle_error(target_info, e, 'sns:get_topic_attributes:')
        return []


sqsQueueAttributeWhitelist = {
    "ApproximateNumberOfMessages",
    "ApproximateNumberOfMessagesDelayed",
    "ApproximateNumberOfMessagesNotVisible",
    "CreatedTimestamp",
    "DelaySeconds",
    "LastModifiedTimestamp",
    "MaximumMessageSize",
    "MessageRetentionPeriod",
    "Policy",
    "QueueArn",
    "ReceiveMessageWaitTimeSeconds",
    "RedrivePolicy",
    "VisibilityTimeout",
    "KmsMasterKeyId",
    "KmsDataKeyReusePeriodSeconds",
    "FifoQueue",
    "ContentBasedDeduplication"
}

def get_sqs_queues(client, queueUrls, target_info):
    try:
        result = []
        for url in queueUrls:
            attrs = client.get_queue_attributes(AttributeNames=['All'], QueueUrl=url)
            whitelistedAttributes = {key: value for (key,value) in attrs['Attributes'].items() if key in sqsQueueAttributeWhitelist}
            tags = {}
            try:
                tags = client.list_queue_tags(QueueUrl=url)['Tags']
            except Exception as e:
                print('Error fetching tag info for SQS Queue "{url}".\nError: {error}'.format(url=url, error=str(e)))

            result.append({
                'Attributes': whitelistedAttributes,
                'QueueUrl': url,
                'Tags': tags,
            })
        return result
    except Exception as e:
        handle_error(target_info, e, 'sqs:get_queue_attributes:')
        return []


def get_dynamoDB_tables(client, tableNames, target_info):
    try:
        response = [client.describe_table(
            TableName=tableName)['Table'] for tableName in tableNames]
        return response
    except Exception as e:
        handle_error(target_info, e, 'dynamodb:describe_table')
        return []

def filter_s3_buckets_to_target_region(client, buckets, target_info):
    try:
        result = []
        for bucket in buckets:
            attrs = client.get_bucket_location(Bucket=bucket['Name'])
            region = attrs['LocationConstraint']
            if region == None:
                region = 'us-east-1'
            if region == target_info.region:
                result.append(bucket)
        return result
    except Exception as e:
        handle_error(target_info, e, 's3:get_bucket_location:')
        return []

def get_complete_albs(client, albs, targetGroups):
    albsResult = []
    targetGroupsResult = []

    resourceArns = []
    arnToTypeMap = {}
    arnToObjMap = {}
    for alb in albs:
        arn = alb['LoadBalancerArn']
        resourceArns.append(arn)
        arnToTypeMap[arn] = 'alb'
        arnToObjMap[arn] = alb
    for group in targetGroups:
        arn = group['TargetGroupArn']
        resourceArns.append(arn)
        arnToTypeMap[arn] = 'group'
        arnToObjMap[arn] = group

    tagInfoForAllResources = []
    try:
        chunkedListOfArns = chunk_list(resourceArns, 20)
        listOfTagLists = [client.describe_tags(ResourceArns=l)['TagDescriptions'] for l in chunkedListOfArns]
        tagInfoForAllResources = flatten_list(listOfTagLists)
    except Exception as e:
        print_err('Error fetching tag info for albs and target groups.\nError: {error}'.format(error=str(e)))

    for tagInfo in tagInfoForAllResources:
        arn = tagInfo['ResourceArn']
        del tagInfo['ResourceArn']
        obj = arnToObjMap.get(arn).copy()
        obj.update(tagInfo)
        resourceType = arnToTypeMap.get(arn)
        if resourceType == 'alb':
            albsResult.append(obj)
        elif resourceType == 'group':
            targetGroupsResult.append(obj)

    return albsResult, targetGroupsResult

def get_complete_cloudfront_distribution(client, distribution):
    result = distribution.copy()
    try:
        tagInfo = client.list_tags_for_resource(Resource=distribution['ARN'])
        del tagInfo['ResponseMetadata']
        result.update(tagInfo)
    except Exception as e:
        print_err('Error fetching tag info for distribution "{name}".\nError: {error}'.format(name=distribution['ARN'], error=str(e)))
        result['Tags'] = {
            'Items': []
        }
    return result

def get_complete_dynamodb_table(client, table):
    result = table.copy()
    try:
        paginator = client.get_paginator('list_tags_of_resource')
        page_iterator = paginator.paginate(ResourceArn=table['TableArn'])
        list_of_tag_lists = map(lambda page: page['Tags'], page_iterator)
        result['Tags'] = flatten_list(list_of_tag_lists)
    except Exception as e:
        print_err('Error fetching tag info for dynamodb table "{arn}".\nError: {error}'.format(arn=table['TableArn'], error=str(e)))
        result['Tags'] = []

    return result

def get_complete_elbs(client, elbs):
    result = []

    elbNames = []
    elbMap = {}
    for val in elbs:
        elbName = val['LoadBalancerName']
        elbNames.append(elbName)
        elbMap[elbName] = val

    tagInfoForAllElbs = []
    try:
        if len(elbNames) > 0:
            chunkedListOfArns = chunk_list(elbNames, 20)
            listOfTagLists = [client.describe_tags(LoadBalancerNames=l)['TagDescriptions'] for l in chunkedListOfArns]
            tagInfoForAllElbs = flatten_list(listOfTagLists)
    except Exception as e:
        print_err('Error fetching tag info for elbs.\nError: {error}'.format(error=str(e)))

    for tagInfo in tagInfoForAllElbs:
        elbName = tagInfo['LoadBalancerName']
        completeElb = elbMap.get(elbName).copy()
        completeElb.update(tagInfo)
        result.append(completeElb)

    return result

rds_engine_filter = {
    'Name': 'engine',
    'Values': [
        'aurora',
        'aurora-mysql',
        'aurora-postgresql',
        'mariadb',
        'mysql',
        'oracle-ee',
        'oracle-ee-cdb',
        'oracle-se2',
        'oracle-se2-cdb',
        'postgres',
        'sqlserver-ee',
        'sqlserver-se',
        'sqlserver-ex',
        'sqlserver-web',
    ]
},
docDB_engine_filter = {
    'Name': 'engine',
    'Values': ['docdb']
},

def get_complete_rds_resource(client, resource, arnProp):
    arn = resource[arnProp]
    result = resource.copy()
    try:
        tagInfo = client.list_tags_for_resource(ResourceName=arn)
        del tagInfo['ResponseMetadata']
        result.update(tagInfo)
    except Exception as e:
        print_err('Error fetching tag info for rds resource with ARN: "{arn}".\nError: {error}'.format(arn=arn, error=str(e)))
        result['TagList'] = []
    return result

def get_complete_eventbridge_resource(client, resource):
    arn = resource['Arn']
    result = resource.copy()
    try:
        tag_list = client.list_tags_for_resource(ResourceARN=arn)['Tags']
        result['Tags'] = tag_list
    except Exception as e:
        print_err('Error fetching tag info for EventBridge with ARN: "{arn}".\nError: {error}'.format(arn=arn, error=str(e)))
        result['Tags'] = []
    return result

def get_complete_cloudtrail_trail(client, resource):
    arn = resource['TrailARN']
    result = resource.copy()
    try:
        tagInfo = client.list_tags(ResourceIdList=[arn])
        result['TagList'] = tagInfo['ResourceTagList'][0]['TagsList']
        for tag in result['TagList']:
            for label in ['Key', 'Value']:
                if label in tag:
                    tag[label.lower()] = tag[label]
                    del tag[label]
    except Exception as e:
        print_err('Error fetching tag info for cloudtrail trail with ARN: "{arn}".\nError: {error}'.format(arn=arn, error=str(e)))
        result['TagList'] = []
    return result


def get_complete_s3_bucket(client, bucket):
    result = bucket.copy()
    try:
        tagInfo = client.get_bucket_tagging(Bucket=bucket['Name'])
        del tagInfo['ResponseMetadata']
        result.update(tagInfo)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchTagSet':
            print_err('Error ({code}) fetching tag info for bucket "{name}".\nError: {error}'.format(code=e.response['Error']['Code'], name=bucket['Name'], error=str(e)))
        result['TagSet'] = []

    try:
        policyStatus = client.get_bucket_policy_status(Bucket=bucket['Name'])
        del policyStatus['ResponseMetadata']
        result.update(policyStatus['PolicyStatus'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
            print_err('Error ({code}) fetching policy info for bucket "{name}".\nError: {error}'.format(code=e.response['Error']['Code'], name=bucket['Name'], error=str(e)))
        result['IsPublic'] = False

    try:
        encryptionInfo = client.get_bucket_encryption(Bucket=bucket['Name'])
        del encryptionInfo['ResponseMetadata']
        result.update(encryptionInfo['ServerSideEncryptionConfiguration'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] != 'ServerSideEncryptionConfigurationNotFoundError':
            print_err('Error ({code}) fetching encryption info for bucket "{name}".\nError: {error}'.format(code=e.response['Error']['Code'], name=bucket['Name'], error=str(e)))
        result['Rules'] = []

    try:
        notificationConfiguration = client.get_bucket_notification_configuration(Bucket=bucket['Name'])
        del notificationConfiguration['ResponseMetadata']
        result.update(notificationConfiguration)
    except botocore.exceptions.ClientError as e:
        result['LambdaFunctionConfigurations'] = []

    return result

def get_complete_sns_topic(client, topic):
    result = topic.copy()
    try:
        tagInfo = client.list_tags_for_resource(ResourceArn=topic['TopicArn'])
        del tagInfo['ResponseMetadata']
        result.update(tagInfo)
    except Exception as e:
        print_err('Error fetching tag info for topic "{name}".\nError: {error}'.format(name=topic['TopicArn'], error=str(e)))
        result['Tags'] = []
    return result

def mixin_resource_record_sets(route53, zone_id_to_zone):
    for zone_id, zone in zone_id_to_zone.items():
        result = route53.list_resource_record_sets(HostedZoneId = zone_id)
        all_records = result.get("ResourceRecordSets") if "ResourceRecordSets" in result else []
        while "NextRecordName" in result:
            result = route53.list_resource_record_sets(HostedZoneId = zone_id, StartRecordName = result["NextRecordName"])
            if "ResourceRecordSets" in result:
                all_records.extend(result.get("ResourceRecordSets"))
        zone["ResourceRecordSets"] = all_records

def mixin_hosted_zone_tags(route53, zone_id_to_zone):
    for zone_id, zone in zone_id_to_zone.items():
        stripped_id = zone_id.split("/hostedzone/")[1]
        result = route53.list_tags_for_resource(ResourceId = stripped_id, ResourceType = "hostedzone")
        tags = result.get("ResourceTagSet").get("Tags", []) if "ResourceTagSet" in result else []
        zone["Tags"] = tags

def list_hosted_zones(route53):
    result = route53.list_hosted_zones()
    all_hosted_zones = result.get("HostedZones") if "HostedZones" in result else []
    while "NextMarker" in result:
        result = route53.list_hosted_zones(Marker = result["NextMarker"])
        if "HostedZones" in result:
            all_hosted_zones.extend(result.get("HostedZones"))
    return all_hosted_zones

def get_hosted_zones(route53, target_info):
    resource_name = "route53:list_hosted_zones"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        all_hosted_zones = list_hosted_zones(route53)
        zone_id_to_zone = {}
        for z in all_hosted_zones:
            zone_id_to_zone[z["Id"]] = z
        mixin_resource_record_sets(route53, zone_id_to_zone)
        mixin_hosted_zone_tags(route53, zone_id_to_zone)
        return all_hosted_zones
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def list_ecs_clusters(ecs):
    result = ecs.list_clusters()
    all_clusters = result.get("clusterArns") if "clusterArns" in result else []
    while "nextToken" in result:
        result = ecs.list_clusters(nextToken = result["nextToken"])
        if "clusterArns" in result:
            all_clusters.extend(result.get("clusterArns"))
    return all_clusters


def list_ecs_services(ecs, cluster):
    all_services = []
    result = ecs.list_services(cluster=cluster)
    if "serviceArns" in result:
        all_services.extend(result.get("serviceArns"))
    while "nextToken" in result:
        result = ecs.list_services(nextToken = result["nextToken"])
        if "serviceArns" in result:
            all_services.extend(result.get("serviceArns"))
    return all_services


def list_ecs_tasks(ecs, cluster):
    all_tasks = []
    result = ecs.list_tasks(cluster=cluster)
    if "taskArns" in result:
        all_tasks.extend(result.get("taskArns"))
    while "nextToken" in result:
        result = ecs.list_tasks(nextToken = result["nextToken"])
        if "taskArns" in result:
            all_tasks.extend(result.get("taskArns"))
    return all_tasks


def get_ecs_clusters(ecs, target_info):
    resource_name = "ecs:describe_clusters"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        clusters = list_ecs_clusters(ecs)
        r = []
        step = 100
        for i in range(0, len(clusters), step):
            r.extend(ecs.describe_clusters(clusters=clusters[i:i+step]).get("clusters", []))
        return r
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def get_ecs_services(ecs, target_info):
    resource_name = "ecs:describe_services"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        clusters = list_ecs_clusters(ecs)
        r = []
        for cluster in clusters:
            services = list_ecs_services(ecs, cluster)
            step = 10
            for i in range(0, len(services), step):
                r.extend(ecs.describe_services(cluster=cluster, services=services[i:i+step]).get("services", []))

        # removing unimportant info that bloats JSON
        for service in r:
            del service["events"]

        return r
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def get_ecs_tasks(ecs, target_info):
    resource_name = "ecs:describe_tasks"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        clusters = list_ecs_clusters(ecs)
        r = []
        for cluster in clusters:
            tasks = list_ecs_tasks(ecs, cluster)
            step = 100
            for i in range(0, len(tasks), step):
                r.extend(ecs.describe_tasks(cluster=cluster, tasks=tasks[i:i+step], include=["TAGS"]).get("tasks", []))
        return r
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def list_efs_file_systems(efs):
    result = efs.describe_file_systems()
    all_file_systems = result.get("FileSystems")
    while "NextMarker" in result:
        result = efs.describe_file_systems(Marker = result["NextMarker"])
        if "FileSystems" in result:
            all_file_systems.extend(result.get("FileSystems"))
    return all_file_systems

def get_efs_file_systems(efs, target_info):
    resource_name = "efs:describe_file_systems"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        file_systems = list_efs_file_systems(efs)
        return file_systems
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def list_eks_clusters(eks):
    result = eks.list_clusters()
    all_clusters = result.get("clusters") if "clusters" in result else []
    while "nextToken" in result:
        result = eks.list_clusters(nextToken = result["nextToken"])
        if "clusters" in result:
            all_clusters.extend(result.get("clusters"))
    return all_clusters

def get_eks_cluster(eks, target_info):
    resource_name = "eks:describe_cluster"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        clusters = list_eks_clusters(eks)
        all_clusters = []
        for cluster in clusters:
            all_clusters.append(eks.describe_cluster(name=cluster).get("cluster", []))
        return all_clusters
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def list_emr_clusters(emr):
    result = emr.list_clusters()
    all_clusters = result.get("Clusters") if "Clusters" in result else []
    while "nextToken" in result:
        result = emr.list_clusters(nextToken = result["nextToken"])
        if "Clusters" in result:
            all_clusters.extend(result.get("Clusters"))
    return all_clusters

def get_emr_cluster(emr, target_info):
    resource_name = "emr:describe_cluster"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        clusters = list_emr_clusters(emr)
        all_clusters = []
        for cluster in clusters:
            all_clusters.append(emr.describe_cluster(ClusterId=cluster["Id"]).get("Cluster", {}))
        return all_clusters
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def list_glacier_vaults(glacier):
    result = glacier.list_vaults()
    all_vaults = result.get("VaultList") if "VaultList" in result else []
    return all_vaults

def get_glacier_vaults(glacier, target_info):
    resource_name = "glacier:describe_vault"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        vaults = list_glacier_vaults(glacier)
        all_vaults = []
        for vault in vaults:
            described_vault = glacier.describe_vault(vaultName=vault.get("VaultName"))
            del described_vault['ResponseMetadata']
            all_vaults.append(described_vault)
        return all_vaults
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def list_state_machines(stepfunctions):
    def append_state_machine_arns(result, all_state_machine_arns):
        all_state_machines = result.get("stateMachines", [])
        for state_machine in all_state_machines:
            if "stateMachineArn" in state_machine:
                all_state_machine_arns.append(state_machine.get("stateMachineArn"))
    all_state_machine_arns = []
    result = stepfunctions.list_state_machines()
    append_state_machine_arns(result, all_state_machine_arns)
    while "nextToken" in result:
        result = stepfunctions.list_state_machines(nextToken = result["nextToken"])
        append_state_machine_arns(result, all_state_machine_arns)
    return all_state_machine_arns

def get_state_machines(stepfunctions, target_info):
    resource_name = "stepfunctions:describe_state_machine"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        all_state_machines = list_state_machines(stepfunctions)
        result = []
        for state_machine in all_state_machines:
            response = stepfunctions.describe_state_machine(stateMachineArn = state_machine)
            if "ResponseMetadata" in response:
                del response["ResponseMetadata"]
            response["tags"] = get_stepfunctions_tags(stepfunctions, target_info, state_machine)
            result.append(response)
        return result
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def list_activities(stepfunctions):
    def append_activity_arns(result, all_activity_arns):
        all_activities = result.get("activities", [])
        for activity in all_activities:
            if "activityArn" in activity:
                all_activity_arns.append(activity.get("activityArn"))
    all_activity_arns = []
    result = stepfunctions.list_activities()
    append_activity_arns(result, all_activity_arns)
    while "nextToken" in result:
        result = stepfunctions.list_activities(nextToken = result["nextToken"])
        append_activity_arns(result, all_activity_arns)
    return all_activity_arns

def get_activities(stepfunctions, target_info):
    resource_name = "stepfunctions:describe_activity"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        all_activities = list_activities(stepfunctions)
        result = []
        for activity in all_activities:
            response = stepfunctions.describe_activity(activityArn = activity)
            if "ResponseMetadata" in response:
                del response["ResponseMetadata"]
            response["tags"] = get_stepfunctions_tags(stepfunctions, target_info, activity)
            result.append(response)
        return result
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def get_stepfunctions_tags(stepfunctions, target_info, resource_arn):
    resource_name = "stepfunctions:list_tags_for_resource"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        response = stepfunctions.list_tags_for_resource(resourceArn = resource_arn)
        return response["tags"]
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return {}

def get_elasticsearch_domains(elasticsearch, target_info):
    resource_name = "elasticsearch:describe_elasticsearch_domains"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        domain_names = [d['DomainName'] for d in elasticsearch.list_domain_names()['DomainNames']]

        # can only request up to 5 elasticsearch domains at a time
        grouped_domain_names = [domain_names[x:x+5] for x in range(0, len(domain_names), 5)]
        elasticsearch_domains = []
        for grouped_names in grouped_domain_names:
            elasticsearch_domains += elasticsearch.describe_elasticsearch_domains(DomainNames = grouped_names)['DomainStatusList']

        for domain in elasticsearch_domains:
            domain.pop("LogPublishingOptions", None)
            domain["TagList"] = get_elasticsearch_tags(elasticsearch, target_info, domain['ARN'])
        return elasticsearch_domains
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def get_elasticsearch_tags(elasticsearch, target_info, resource_arn):
    resource_name = "elasticsearch:list_tags"
    try:
        response = elasticsearch.list_tags(ARN = resource_arn)
        return response["TagList"]
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def list_kinesis_data_stream_names(kinesis):
    try:
        response = kinesis.list_streams()
        all_stream_names = response['StreamNames']
        while response['HasMoreStreams']:
            response = kinesis.list_streams(ExclusiveStartStreamName = all_stream_names[-1])
            all_stream_names.extend(response['StreamNames'])
        return all_stream_names
    except:
        return []

def list_kinesis_data_stream_shards(kinesis, stream_name):
    try:
        response = kinesis.list_shards(StreamName = stream_name)
        all_shards = response['Shards']
        while 'NextToken' in response:
            response = kinesis.list_shards(NextToken = response['NextToken'])
            all_shards.extend(response['Shards'])
        return all_shards
    except:
        return []

def list_kinesis_data_stream_tags(kinesis, stream_name):
    try:
        response = kinesis.list_tags_for_stream(StreamName = stream_name)
        all_tags = response['Tags']
        while response['HasMoreTags']:
            response = kinesis.list_tags_for_stream(ExclusiveStartTagKey = all_tags[-1]['Key'])
            all_tags.extend(response['Tags'])
        return all_tags
    except:
        return []

def get_kinesis_data_streams(kinesis, target_info):
    resource_name = "kinesis:list_streams"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        all_stream_names = list_kinesis_data_stream_names(kinesis)
        data_streams = []
        for stream_name in all_stream_names:
            response = kinesis.describe_stream(StreamName = stream_name)
            data_stream = response['StreamDescription']
            if data_stream['HasMoreShards']:
                data_stream['Shards'] = list_kinesis_data_stream_shards(kinesis, stream_name)
            data_stream['Tags'] = list_kinesis_data_stream_tags(kinesis, stream_name)
            data_streams.append(data_stream)
        return data_streams
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def list_kinesis_delivery_stream_names(firehose):
    try:
        response = firehose.list_delivery_streams()
        all_stream_names = response['DeliveryStreamNames']
        while response['HasMoreDeliveryStreams']:
            response = firehose.list_streams(ExclusiveStartDeliveryStreamName = all_stream_names[-1])
            all_stream_names.extend(response['DeliveryStreamNames'])
        return all_stream_names
    except:
        return []

def list_kinesis_delivery_stream_tags(firehose, stream_name):
    try:
        response = firehose.list_tags_for_delivery_stream(DeliveryStreamName = stream_name)
        all_tags = response['Tags']
        while response['HasMoreTags']:
            response = firehose.list_tags_for_delivery_stream(ExclusiveStartTagKey = all_tags[-1]['Key'])
            all_tags.extend(response['Tags'])
        return all_tags
    except:
        return []

def get_kinesis_delivery_streams(firehose, target_info):
    resource_name = "firehose:list_delivery_streams"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        all_delivery_stream_names = list_kinesis_delivery_stream_names(firehose)
        delivery_streams = []
        for stream_name in all_delivery_stream_names:
            response = firehose.describe_delivery_stream(DeliveryStreamName = stream_name)
            delivery_stream = response['DeliveryStreamDescription']
            delivery_stream['Tags'] = list_kinesis_delivery_stream_tags(firehose, stream_name)
            delivery_streams.append(delivery_stream)
        return delivery_streams
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def get_account_resources(session, target_info, calculateCount):
    cloudfront = session.create_client(
        'cloudfront', region_name=target_info.region)
    route53 = session.create_client('route53', region_name=target_info.region)

    cloudfrontDistributions = get_cloudfront_distributions(
        cloudfront, target_info)
    hosted_zones = get_hosted_zones(route53, target_info)

    if not COUNT:
        print('Getting additional metadata for account resources')
        cloudfrontDistributions = [get_complete_cloudfront_distribution(cloudfront, distribution) for distribution in cloudfrontDistributions]

    numOfResources = 0
    numOfComputeResources = 0

    if calculateCount:
        numOfResources = len(cloudfrontDistributions) \
        + len(hosted_zones)


    return [{
        'cloudFront': {
            'distributions': cloudfrontDistributions,
        },
        'route53': {
            'hostedZones': hosted_zones,
        }
    }, {
        'resources': numOfResources,
        'computeResources': numOfComputeResources,
    }]

def getElastiCacheClusters(elastiCache, target_info):
    try:
        clusters = make_request(elastiCache.describe_cache_clusters, target_info, 'elasticache:describe_cache_clusters', 'CacheClusters')
        return clusters
    except Exception as e:
        handle_error(target_info, e, 'Could not get ElastiCache Clusters')
        return []

def getElastiCacheSubnetGroups(elastiCache, target_info):
    try:
        subnetGroups = make_request(elastiCache.describe_cache_subnet_groups, target_info, 'elasticache:describe_cache_subnet_groups', 'CacheSubnetGroups')
        return subnetGroups
    except Exception as e:
        handle_error(target_info, e, 'Could not get ElastiCache SubnetGroups')
        return []

def getNetworkFirewalls(session, target_info):
    try:
        client = session.create_client('network-firewall', region_name=target_info.region)
        networkFirewalls = get_network_firewalls(client, target_info)
        return networkFirewalls
    except Exception as e:
        handle_error(target_info, e, 'Could not create client:')
        return []

def list_event_buses(events):
    result = events.list_event_buses()
    all_event_buses = result.get("EventBuses") if "EventBuses" in result else []
    while "NextToken" in result:
        result = events.list_event_buses(NextToken = result["NextToken"])
        if "EventBuses" in result:
            all_event_buses.extend(result.get("EventBuses"))
    return all_event_buses

def get_event_buses(events, target_info):
    resource_name = "events:describe_event_bus"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        event_buses = list_event_buses(events)
        all_event_buses = []
        for event_bus in event_buses:
            described_event_buses = events.describe_event_bus(Name=event_bus.get("Name"))
            del described_event_buses['ResponseMetadata']
            all_event_buses.append(described_event_buses)
        return all_event_buses
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def get_eventbridge_rules(client, target_info):
    try:
        print('Executing {account}:{region}:events:list_eventbridge_rules'.format(account=target_info.profile_name, region=target_info.region))
        response = client.list_rules()
        eventbridge_rules = response['Rules']

        while 'NextToken' in response:
            response = client.list_rules(NextToken = response['NextToken'])
            eventbridge_rules.extend(response['Rules'])
        for rule in eventbridge_rules:
            try:
                rule_def = client.describe_rule(Name=rule['Name'], EventBusName=rule['EventBusName'])
                if 'CreatedBy' in rule_def:
                    rule['CreatedBy'] = rule_def['CreatedBy']
            except Exception as e:
                print('Error fetching Rule definition for EventBridge Rule "{arn}"\nError: {error}'.format(arn=rule['Arn'], error=str(e)))
        return eventbridge_rules
    except Exception as e:
        handle_error(target_info, e, 'eventbridge:list_eventbridge_rules')
        if COUNT:
            print_err('Unable to count resources because of error requesting required resources')
            exit()
        else:
            return []

def get_msk_clusters(client, target_info):
    resource_name = "kafka:list_clusters_v2"
    print('Executing {account}:{region}:{resource_name}'.format(account=target_info.profile_name, region=target_info.region, resource_name=resource_name))
    try:
        result = client.list_clusters_v2()
        all_msk_clusters = result['ClusterInfoList'] if 'ClusterInfoList' in result else []
        while 'NextToken' in result:
            result = client.list_clusters_v2(NextToken=result['NextToken'])
            if 'ClusterInfoList' in result:
                all_msk_clusters.extend(result['ClusterInfoList'])
        return all_msk_clusters
    except Exception as e:
        handle_error(target_info, e, resource_name)
        return []

def get_cognito_user_pools(client, target_info):
    try:
        print('Executing {account}:{region}:cognito-idp:list_user_pools'.format(account=target_info.profile_name, region=target_info.region))
        response = client.list_user_pools(MaxResults=60)
        pools = response['UserPools']

        while 'NextToken' in response:
            response = client.list_user_pools(NextToken=response['NextToken'], MaxResults=60)
            pools.extend(response['UserPools'])
        pools_defs = []
        for pool in pools:
            try:
                pool_def = client.describe_user_pool(UserPoolId=pool['Id'])
                pools_defs.append(pool_def)
            except Exception as e:
                print('Error fetching User Pool definition for Cognito User Pools "{arn}"\nError: {error}'.format(arn=rule['Arn'], error=str(e)))
        return pools_defs
    except Exception as e:
        handle_error(target_info, e, 'cognito-idp:list_user_pools')
        if COUNT:
            print_err('Unable to count resources because of error requesting required resources')
            exit()
        else:
            return []

def create_json(session, target_info):
    elbv2 = session.create_client('elbv2', region_name=target_info.region)
    apigateway = session.create_client('apigateway', region_name=target_info.region)
    apigatewayv2 = session.create_client('apigatewayv2', region_name=target_info.region)
    appsync = session.create_client('appsync', region_name=target_info.region)
    autoscaling = session.create_client(
        'autoscaling', region_name=target_info.region)
    cloudtrail = session.create_client('cloudtrail', region_name=target_info.region)
    docDB = session.create_client('docdb', region_name=target_info.region)
    dynamodb = session.create_client(
        'dynamodb', region_name=target_info.region)
    ec2 = session.create_client('ec2', region_name=target_info.region)
    elastiCache = session.create_client('elasticache', region_name=target_info.region)
    elb = session.create_client('elb', region_name=target_info.region)
    emrClient = session.create_client('emr', region_name=target_info.region)
    lambdaClient = session.create_client(
        'lambda', region_name=target_info.region)
    rds = session.create_client('rds', region_name=target_info.region)
    redshift = session.create_client(
        'redshift', region_name=target_info.region)
    s3 = session.create_client('s3', region_name=target_info.region)
    sns = session.create_client('sns', region_name=target_info.region)
    sqs = session.create_client('sqs', region_name=target_info.region)
    ecs = session.create_client('ecs', region_name=target_info.region)
    efs = session.create_client('efs', region_name=target_info.region)
    eks = session.create_client('eks', region_name=target_info.region)
    glacier = session.create_client('glacier', region_name=target_info.region)
    stepfunctions = session.create_client('stepfunctions', region_name=target_info.region)
    elasticsearch = session.create_client('es', region_name=target_info.region)
    kinesis = session.create_client('kinesis', region_name=target_info.region)
    firehose = session.create_client('firehose', region_name=target_info.region)
    eventbridge = session.create_client('events', region_name=target_info.region)
    msk = session.create_client('kafka', region_name=target_info.region)
    cognito = session.create_client('cognito-idp', region_name=target_info.region)

    apiGateways = get_complete_api_gateways(apigateway, target_info)
    apiGatewayV2s = get_complete_api_gateway_v2s(apigatewayv2, target_info)

    try:
        snsTopics = make_request(
            sns.list_topics, target_info, 'sns:list_topics', 'Topics')
    except Exception as e:
        handle_error(target_info, e, "sns:list_topics")
        snsTopics = []

    try:
        sqsQueueUrls = make_request(
            sqs.list_queues, target_info, 'sqs:list_queues', 'QueueUrls')
    except Exception as e:
        handle_error(target_info, e, "sqs.list_queues")
        sqsQueueUrls = []

    try:
        docDbClusters = make_request(docDB.describe_db_clusters, target_info, 'docdb.describe_db_clusters', 'DBClusters', False, docDB_engine_filter)
    except Exception as e:
        handle_error(target_info, e, "docDB.describe_db_clusters")
        docDbClusters = []

    try:
        dynamoDbTableNames = make_request(
            dynamodb.list_tables, target_info, 'dynamodb:list_tables', 'TableNames')
    except Exception as e:
        handle_error(target_info, e, "dynamodb.list_tables")
        dynamoDbTableNames = []

    dynamoDbTables = get_dynamoDB_tables(dynamodb, dynamoDbTableNames, target_info)

    try:
        vpcs = make_request(ec2.describe_vpcs, target_info,
                        'ec2:describe_vpcs', 'Vpcs')
    except Exception as e:
        handle_error(target_info, e, "ec2:describe_vpcs")
        vpcs = []

    try:
        subnets = make_request(ec2.describe_subnets, target_info,
                           'ec2:describe_subnets', 'Subnets')
    except Exception as e:
        handle_error(target_info, e, "ec2:describe_subnets")
        subnets = []

    try:
        instances = make_request(
            ec2.describe_instances, target_info, 'ec2:describe_instances', 'Reservations', True)
    except Exception as e:
        handle_error(target_info, e, "ec2:describe_instances")
        instances = []

    try:
        volumes = make_request(ec2.describe_volumes, target_info,
                           'ec2:describe_volumes', 'Volumes')
    except Exception as e:
        handle_error(target_info, e, "ec2.describe_volumes")
        volumes = []

    try:
        networkAcls = make_request(
            ec2.describe_network_acls, target_info, 'ec2:describe_network_acls', 'NetworkAcls')
    except Exception as e:
        handle_error(target_info, e, "ec2:describe_network_acls")
        networkAcls = []

    elastiCacheClusters = getElastiCacheClusters(elastiCache, target_info)
    elastiCacheSubnetGroups = getElastiCacheSubnetGroups(elastiCache, target_info)

    try:
        elbLoadBalancers = make_request(
            elb.describe_load_balancers, target_info, 'elb:describe_load_balancers', 'LoadBalancerDescriptions')
    except Exception as e:
        handle_error(target_info, e, "elb:describe_load_balancers")
        elbLoadBalancers = []

    try:
        albLoadBalancers = make_request(
            elbv2.describe_load_balancers, target_info, 'elbv2:describe_load_balancers', 'LoadBalancers')
    except Exception as e:
        handle_error(target_info, e, "elbv2:describe_load_balancers")
        albLoadBalancers = []

    try:
        customerGateways = make_request(ec2.describe_customer_gateways, target_info, 'ec2:describe_customer_gateway', 'CustomerGateways')
    except Exception as e:
        handle_error(target_info, e, "ec2:describe_customer_gateway")
        customerGateways = []

    try:
        vpn_connections = make_request(
            ec2.describe_vpn_connections, target_info, 'ec2:describe_vpn_connections', 'VpnConnections')
    except Exception as e:
        handle_error(target_info, e, "ec2:describe_vpn_connections")
        vpn_connections = []

    try:
        vpnGateways = make_request(
            ec2.describe_vpn_gateways, target_info, 'ec2:describe_vpn_gateways', 'VpnGateways')
    except Exception as e:
        handle_error(target_info, e, "ec2:describe_vpn_gateways")
        vpnGateways = []

    try:
        vpcPeeringConnections = make_request(ec2.describe_vpc_peering_connections,
            target_info, 'ec2:describe_vpc_peering_connections', 'VpcPeeringConnections')
    except Exception as e:
        handle_error(target_info, e, "ec2:describe_vpc_peering_connections")
        vpcPeeringConnections = []

    targetGroups = get_target_groups(elbv2, target_info)

    try:
        autoscalingGroups = make_request(autoscaling.describe_auto_scaling_groups,
                                     target_info, 'autoscaling:describe_auto_scaling_groups', 'AutoScalingGroups')
    except Exception as e:
        handle_error(target_info, e, "autoscaling:describe_auto_scaling_groups")
        autoscalingGroups = []

    try:
        allS3Buckets = make_request(s3.list_buckets, target_info,
                             's3:list_buckets', 'Buckets')
    except Exception as e:
        handle_error(target_info, e, "s3:list_buckets")
        allS3Buckets = []

    bucketsForRegion = filter_s3_buckets_to_target_region(s3, allS3Buckets, target_info)
    topics = get_sns_topics(sns, snsTopics, target_info)

    try:
        cloudTrailTrails = make_request(cloudtrail.describe_trails, target_info, 'cloudtrail:describe_trails', 'trailList')
        cloudTrailTrails = [trail for trail in cloudTrailTrails if trail['HomeRegion'] == target_info.region]
    except Exception as e:
        handle_error(target_info, e, "cloudtrail:describe_trails")
        cloudTrailTrails = []

    queues = get_sqs_queues(sqs, sqsQueueUrls, target_info)

    try:
        rdsDbInstances = make_request(
            rds.describe_db_instances, target_info, 'rds.describe_db_instances', 'DBInstances', False, rds_engine_filter)
    except Exception as e:
        handle_error(target_info, e, "rds.describe_db_instances")
        rdsDbInstances = []

    try:
        rdsDbProxies = make_request(
            rds.describe_db_proxies, target_info, 'rds.describe_db_proxies', 'DBProxies', False, rds_engine_filter)
    except Exception as e:
        handle_error(target_info, e, "rds.describe_db_proxies")
        rdsDbProxies = []


    try:
        internetGateways = make_request(
            ec2.describe_internet_gateways, target_info, 'ec2:describe_internet_gateways', 'InternetGateways')
    except Exception as e:
        handle_error(target_info, e, "ec2:describe_internet_gateways")
        internetGateways = []

    try:
        natGateways = make_request(
            ec2.describe_nat_gateways, target_info, 'ec2:describe_nat_gateways', 'NatGateways')
    except Exception as e:
        handle_error(target_info, e, "ec2:describe_nat_gateways")
        natGateways = []

    transitGateways = get_transit_gateways(ec2, target_info)

    try:
        routeTables = make_request(
            ec2.describe_route_tables, target_info, 'ec2:describe_route_tables', 'RouteTables')
    except Exception as e:
        handle_error(target_info, e, "ec2:describe_route_tables")
        routeTables = []

    try:
        vpcEndpoints = make_request(
            ec2.describe_vpc_endpoints, target_info, 'ec2:describe_vpc_endpoints', 'VpcEndpoints')
    except Exception as e:
        handle_error(target_info, e, "ec2:describe_vpc_endpoints")
        vpcEndpoints = []

    try:
        vpcEndpointConnections = make_request(
            ec2.describe_vpc_endpoint_connections, target_info, 'ec2:describe_vpc_endpoint_connections', 'VpcEndpointConnections')
    except Exception as e:
        handle_error(target_info, e, "ec2:describe_vpc_endpoint_connections")
        vpcEndpointConnections = []

    graphqlApis = get_appsync_graphqlapis(appsync, target_info)
    snsSubscriptions = get_sns_subscriptions(sns, target_info)
    lambdaFunctions = get_lambda_functions(lambdaClient, target_info)
    lambdaEventSourceMapping = get_lambda_event_source_mappings(lambdaClient, target_info)
    networkFirewalls = getNetworkFirewalls(session, target_info)

    try:
        rdsDbClusters = make_request(
            rds.describe_db_clusters, target_info, 'rds.describe_db_clusters', 'DBClusters', False, rds_engine_filter)
    except Exception as e:
        handle_error(target_info, e, "rds.describe_db_clusters")
        rdsDbClusters = []

    try:
        redshiftClusters = make_request(
            redshift.describe_clusters, target_info, 'rds.describe_clusters', 'Clusters')
    except Exception as e:
        handle_error(target_info, e, "rds.describe_clusters")
        redshiftClusters = []

    try:
        securityGroups = make_request(ec2.describe_security_groups, target_info, 'ec2:describe_security_groups', 'SecurityGroups')
    except Exception as e:
        handle_error(target_info, e, "ec2:describe_security_groups")
        securityGroups = []

    try:
        launchConfiguration = make_request(autoscaling.describe_launch_configurations, target_info, 'autoscaling:describe_launch_configurations', 'LaunchConfigurations')
    except Exception as e:
        handle_error(target_info, e, "autoscaling:describe_launch_configurations")
        launchConfiguration = []

    try:
        elasticNetworkInterfaces = make_request(ec2.describe_network_interfaces, target_info, 'ec2:describe_network_interfaces', 'NetworkInterfaces')
    except Exception as e:
        handle_error(target_info, e, "ec2.describe_network_interfaces")
        elasticNetworkInterfaces = []

    ecsClusters = get_ecs_clusters(ecs, target_info)
    ecsServices = get_ecs_services(ecs, target_info)
    ecsTasks = get_ecs_tasks(ecs, target_info)
    iam_roles = []

    efsFileSystems = get_efs_file_systems(efs, target_info)

    eksClusters = get_eks_cluster(eks, target_info)

    emrClusters = get_emr_cluster(emrClient, target_info)

    stateMachines = get_state_machines(stepfunctions, target_info)
    activities = get_activities(stepfunctions, target_info)

    elasticsearchDomains = get_elasticsearch_domains(elasticsearch, target_info)

    kinesisDataStreams = get_kinesis_data_streams(kinesis, target_info)
    kinesisDeliveryStreams = get_kinesis_delivery_streams(firehose, target_info)

    glacierVaults = get_glacier_vaults(glacier, target_info)

    eventbridgeEventBuses = get_event_buses(eventbridge, target_info)

    eventBridgeRules = get_eventbridge_rules(eventbridge, target_info)

    mskClusters = get_msk_clusters(msk, target_info)

    cognitoUserPools = get_cognito_user_pools(cognito, target_info)

    if not COUNT:
        print('Getting additional metadata for region resources')
        albLoadBalancers, targetGroups = get_complete_albs(elbv2, albLoadBalancers, targetGroups)
        dynamoDbTables = [get_complete_dynamodb_table(dynamodb, table) for table in dynamoDbTables]
        elbLoadBalancers = get_complete_elbs(elb, elbLoadBalancers)
        docDbClusters = [get_complete_rds_resource(docDB, cluster, 'DBClusterArn') for cluster in docDbClusters]
        rdsDbInstances = [get_complete_rds_resource(rds, instance, 'DBInstanceArn') for instance in rdsDbInstances]
        rdsDbClusters = [get_complete_rds_resource(rds, cluster, 'DBClusterArn') for cluster in rdsDbClusters]
        rdsDbProxies = [get_complete_rds_resource(rds, proxy, 'DBProxyArn') for proxy in rdsDbProxies]
        bucketsForRegion = [get_complete_s3_bucket(s3, bucket) for bucket in bucketsForRegion]
        cloudTrailTrails = [get_complete_cloudtrail_trail(cloudtrail, trail) for trail in cloudTrailTrails]
        topics = [get_complete_sns_topic(sns, topic) for topic in topics]
        eventbridgeEventBuses = [get_complete_eventbridge_resource(eventbridge, eventBus) for eventBus in eventbridgeEventBuses]
        eventBridgeRules = [get_complete_eventbridge_resource(eventbridge, rule) for rule in eventBridgeRules]


    num_instances = sum(len(x['Instances']) for x in instances)
    count_data = {
        'computeResources': num_instances + len(lambdaFunctions),
        'resources': len(vpcs) \
            + len(subnets) \
            + num_instances \
            + len(volumes) \
            + len(networkAcls) \
            + len(elbLoadBalancers) \
            + len(albLoadBalancers) \
            + len(apiGateways) \
            + len(apiGatewayV2s) \
            + len(autoscalingGroups) \
            + len(bucketsForRegion) \
            + len(cloudTrailTrails) \
            + len(graphqlApis) \
            + len(queues) \
            + len(topics) \
            + len(snsSubscriptions) \
            + len(rdsDbInstances) \
            + len(rdsDbProxies) \
            + len(internetGateways) \
            + len(natGateways) \
            + len(transitGateways) \
            + len(routeTables) \
            + len(vpcEndpoints) \
            + len(vpn_connections) \
            + len(vpnGateways) \
            + len(vpcPeeringConnections) \
            + len(customerGateways) \
            + len(lambdaFunctions) \
            + len(networkFirewalls) \
            + len(docDbClusters) \
            + len(rdsDbClusters) \
            + len(dynamoDbTables) \
            + len(redshiftClusters) \
            + len(targetGroups) \
            + len(securityGroups) \
            + len(launchConfiguration) \
            + len(iam_roles) \
            + len(ecsClusters) \
            + len(ecsServices) \
            + len(ecsTasks) \
            + len(efsFileSystems) \
            + len(eksClusters) \
            + len(glacierVaults) \
            + len(stateMachines) \
            + len(activities) \
            + len(elastiCacheClusters) \
            + len(elastiCacheSubnetGroups) \
            + len(elasticsearchDomains) \
            + len(elasticNetworkInterfaces) \
            + len(emrClusters) \
            + len(kinesisDataStreams) \
            + len(kinesisDeliveryStreams) \
            + len(eventbridgeEventBuses) \
            + len(eventBridgeRules) \
            + len(mskClusters) \
            + len(cognitoUserPools) \
            + len(lambdaEventSourceMapping)
    }
    infrastructure_data = {
        'alb': {
            'loadBalancersV2': albLoadBalancers,
            'targetGroups': targetGroups,
        },
        'apigateway': {
            'restApis': apiGateways,
        },
        'apigatewayv2': {
            'apis': apiGatewayV2s,
        },
        'appsync': {
            'graphqlApis': graphqlApis,
        },
        'autoscaling': {
            'groups': autoscalingGroups,
            'launchConfiguration': launchConfiguration,
        },
        'cloudtrail': {
            'trails': cloudTrailTrails
        },
        'documentDB': {
            'clusters': docDbClusters,
        },
        'dynamoDB': {
            'tables': dynamoDbTables,
        },
        'ec2': {
            'instances': instances,
            'customerGateways': customerGateways,
            'networkAcls': networkAcls,
            'securityGroups': securityGroups,
            'subnets': subnets,
            'volumes': volumes,
            'vpcs': vpcs,
            'internetGateways': internetGateways,
            'natGateways': natGateways,
            'transitGateways': transitGateways,
            'routeTables': routeTables,
            'vpcEndpoints': vpcEndpoints,
            'vpcEndpointConnections': vpcEndpointConnections,
            'vpnConnections': vpn_connections,
            'vpnGateways': vpnGateways,
            'vpcPeeringConnections': vpcPeeringConnections,
            'elasticNetworkInterfaces': elasticNetworkInterfaces,
        },
        'elasticache': {
            'clusters': elastiCacheClusters,
            'subnetGroups': elastiCacheSubnetGroups,
        },
        'elasticsearch': {
            'domains': elasticsearchDomains,
        },
        'elb': {
            'loadBalancers': elbLoadBalancers,
        },
        'eventbridge': {
            'eventBuses': eventbridgeEventBuses,
            'rules': eventBridgeRules,
        },
        'glacier': {
            'vaults': glacierVaults,
        },
        'iam': {
            'attachedPolicies': [],
            'roles': iam_roles,
            'rolePolicies': [],
        },
        'kinesis': {
            'dataStreams': kinesisDataStreams,
            'deliveryStreams': kinesisDeliveryStreams,
        },
        'lambda': {
            'functions': lambdaFunctions,
            'eventSourceMappings': lambdaEventSourceMapping,
        },
        'msk': {
            'clusters': mskClusters,
        },
        'networkfirewall': {
            'firewalls': networkFirewalls,
        },
        'rds': {
            'dbInstances': rdsDbInstances,
            'dbClusters': rdsDbClusters,
            'dbProxies': rdsDbProxies,
        },
        'redshift': {
            'clusters': redshiftClusters,
        },
        's3': {
            'buckets': bucketsForRegion,
        },
        'sns': {
            'topics': topics,
            'subscriptions': snsSubscriptions,
        },
        'sqs': {
            'queues': queues,
        },
        'ecs': {
            'clusters': ecsClusters,
            'services': ecsServices,
            'tasks': ecsTasks,
        },
        'efs': {
            'fileSystems': efsFileSystems,
        },
        'eks': {
            'eksClusters': eksClusters,
        },
        'emr': {
            'clusters': emrClusters,
        },
        'stepfunctions': {
            'stateMachines': stateMachines,
            'activities': activities,
        },
        'cognito' : {
            'userPools': cognitoUserPools,
        }
    }

    return [
        infrastructure_data,
        count_data
    ]


def get_account(target_info, session):
    try:
        sts = session.create_client('sts', region_name=target_info.region)
        account = make_request(sts.get_caller_identity, target_info,
                               'sts:get_caller_identity', 'Account')
        return account
    except Exception as e:
        handle_error(target_info, e, 'Could not create session:')
        return None

def get_account_aliases(target_info, session):
    try:
        iam = session.create_client('iam')
        account_aliases = make_request(iam.list_account_aliases, target_info,
                                       'iam:list_account_aliases', 'AccountAliases')
        return account_aliases
    except Exception as e:
        handle_error(target_info, e, 'Could not create session:')
        return None

def process_args():
    parser = ArgumentParser()
    parser.add_argument('-r', '--regions', help=usage,
                        nargs='+', type=str, action='append')
    parser.add_argument('-p', '--profile', help=usage,
                        type=str, action='append')
    parser.add_argument(
        '-c', '--count', help="count number of AWS resources", action='store_true')
    parser.add_argument(
        '-a', '--anon', help="anonymize the output of the script", action='store_true')
    parser.add_argument(
        '-o', '--output', help="specify output file name", nargs='?', type=str, action='store')
    return parser.parse_args()


def generateTargets(args):
    profiles = args.profile
    regions = args.regions
    if not profiles or not regions:
        return []

    if len(profiles) != len(regions):
        return []

    profileRegions = list(zip(profiles, regions))
    targets = []
    for profileRegion in profileRegions:
        for region in profileRegion[1]:
            targets.append(AwsImportTarget(profileRegion[0], region))

    return targets

def print_errors():
    print_err("\nErrors occurred while importing:")
    for error in ERRORS:
        print_err(error)

def print_to_file(contents, file_name, message, pretty_print):
    with open(file_name, 'w') as f:
        indent = 4 if pretty_print else None
        json.dump(contents, f, indent=indent, cls=DateTimeEncoder)
        print(message)

def anonymize(val):
    if isinstance(val, dict):
        obj = {}
        for key, value in val.items():
            obj[key] = anonymize(value)
        return obj
    elif isinstance(val, str):
        return encrypt_string(val)[0:12]
    elif isinstance(val, list):
        return [anonymize(i) for i in val]
    elif isinstance(val, datetime):
        return anonymize(str(val))
    else:
        return val

def import_aws():
    args = process_args()
    global COUNT
    global OUT_FILE
    COUNT = args.count
    ANON = args.anon
    OUT_FILE = args.output
    if OUT_FILE and not OUT_FILE.endswith(".json"):
        OUT_FILE += ".json"
    targets = generateTargets(args)

    if not targets:
        print_err(usage, warning=True)
        return

    accounts = {}
    total_resource_count = 0
    total_compute_resource_count = 0

    for target in targets:
        session = botocore.session.Session(profile=target.profile_name)
        account = get_account(target, session)
        account_aliases = get_account_aliases(target, session)
        account_hash = encrypt_string(account)

        if not account:
            handle_error(
                target, 'Could not get account info (double check your profile name / region)', 'Unable to import account:')
            continue

        region_resources = create_json(session, target)

        if COUNT:
            if account_hash not in accounts:
                account_resources = get_account_resources(session, target, args.count)
                total_resource_count += account_resources[1]['resources']
                accounts[account_hash] = {
                    'resourceCount': account_resources[1]['resources'],
                    'computeResourceCount': 0
                }
            accounts[account_hash]['resourceCount'] = accounts[account_hash]['resourceCount'] + region_resources[1]['resources']
            accounts[account_hash]['computeResourceCount'] = accounts[account_hash]['computeResourceCount'] + region_resources[1]['computeResources']
            total_resource_count += region_resources[1]['resources']
            total_compute_resource_count += region_resources[1]['computeResources']
        else:
            if account_hash not in accounts:
                account_resources = get_account_resources(session, target, args.count)
                accounts[account_hash] = {
                    'accountId': account,
		            'accountAliases': account_aliases,
                    'resources': account_resources[0],
                    'regions': []
                }
            accounts[account_hash]['regions'].append({
                'regionId': target.region,
                'resources': region_resources[0]
            })

    if COUNT:
        results = {
            'totalResourceCount': total_resource_count,
            'totalComputeResourceCount': total_compute_resource_count,
            'accounts': accounts
        }
        if ERRORS:
            print_errors()
        if accounts.values():
            out_file = OUT_FILE if OUT_FILE else 'count.json'
            print_to_file(results, out_file, '\nResource count output to ' + out_file, True)
    else:
        results = {
            'accounts': list(accounts.values())
        }
        if ANON:
            results = anonymize(results)
        if ERRORS:
            print_errors()
            if accounts.values():
                print_err("\nYou can import this file, however resources and accounts that experienced errors will not appear", warning=True)
        if accounts.values():
            out_file = OUT_FILE if OUT_FILE else 'aws.json'
            print_to_file(results, out_file, '\nAWS Resources output to ' + out_file, False)


def getBotocoreVersionWarning(pipCommandName):
    return 'WARNING: You are using version ' + botocore.__version__ + ' of the botocore python module.\nThe import in Lucidscale may fail if you are not using version ' + requiredBotocoreVersion + '.\nChange the version by running "' + pipCommandName + ' install --force-reinstall botocore==' + requiredBotocoreVersion + '".\nPress Enter to quit or type "continue" to continue with the script: '

if botocore.__version__ != requiredBotocoreVersion:
    if sys.version_info > (3,0):
        response = input(getBotocoreVersionWarning('pip3'))
    else:
        response = raw_input(getBotocoreVersionWarning('pip'))

    if response != 'continue':
        exit()

if __name__ == "__main__":
    # this enables colorization in windows cmd terminal
    if "Windows" in platform.system():
        os.system('color')
    import_aws()