# --
# File: aws_connector.py
# --
# -----------------------------------------
# AWS Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App
from aws_consts import *

import simplejson as json
import boto3
import datetime


def _json_fallback(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj


# Define the App Class
class AWSConnector(BaseConnector):

    ACTION_ID_AWS_DESCRIBE_INSTANCE = "aws_describe_instance"
    ACTION_ID_AWS_DESCRIBE_USER = "aws_describe_user"
    ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_asset_connectivity"
    ACTION_ID_AWS_DETACH_INSTANCE_FROM_AUTOSCALING_GROUP = "aws_detach_instance_from_autoscaling_group"
    ACTION_AWS_DEREGISTER_INSTANCE_FROM_ELB = "aws_deregister_instance_from_elb"
    ACTION_AWS_DISABLE_INSTANCE_API_TERMINATION = "aws_disable_instance_api_termination"
    ACTION_AWS_SNAPSHOT_VOLUMES = "aws_snapshot_volumes"
    ACTION_AWS_ADD_TO_SECURITY_GROUP = "aws_add_to_security_group"
    ACTION_AWS_ADD_TAG = "aws_add_tag"
    ACTION_AWS_ADD_NETWORKACL_RULE = "aws_network_acl_rule"

    def __init__(self):

        # Call the BaseConnectors init first
        super(AWSConnector, self).__init__()

    def _response_no_data(self, response, obj):

        reservations = response['Reservations']
        # First check if the raw data contains any info
        if (len(reservations == 0)):
            self.debug_print('No data returned', 'Instance not found')
            return True

        return False

    def _test_connectivity(self, param):

        config = self.get_config()

        # get the server
        region = config.get(AWS_REGION)
        aws_access_key_id = config.get(AWS_ACCESS_KEY_ID)
        aws_secret_access_key = config.get(AWS_SECRET_ACCESS_KEY)

        # this if checks the negation of: either region is the only thing that is provided or all region, access key id and key are provided
        if(not((region and aws_access_key_id and aws_secret_access_key) or (region and not aws_access_key_id and not aws_secret_access_key ))):
            self.save_progress("Improper Input Detected")
            return self.get_status()

        self.save_progress("Querying API to check connectivity")

        # Progress
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, region)

        try:
            aws_client = boto3.client('ec2')
            aws_response = aws_client.describe_instances()

            if (len(aws_response['Reservations']) > 0):
                self.set_status(phantom.APP_ERROR, AWS_ERR_API_CONNECTION, e)
                self.append_to_message(AWS_ERR_CONNECTIVITY_TEST)
                return self.get_status()

        except Exception as e:
            self.set_status(phantom.APP_ERROR, AWS_ERR_API_CONNECTION, e)
            self.append_to_message(AWS_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, AWS_SUCC_CONNECTIVITY_TEST)

    def _handle_aws_describe_instance(self, param):

        # Get the config
        config = self.get_config()

        self.debug_print("param", param)

        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # Get AWS Region
        region = config.get(AWS_REGION)
        aws_access_key_id = config.get(AWS_ACCESS_KEY_ID)
        aws_secret_access_key = config.get(AWS_SECRET_ACCESS_KEY)
        instance_id = param[AWS_INSTANCE]

        try:
            if (region and aws_access_key_id and aws_secret_access_key):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
            elif(region and not aws_access_key_id and not aws_secret_access_key ):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region)
            else:
                action_result.set_status(phantom.APP_ERROR, AWS_ERR_REGION, e)
                return action_result.get_status()

            # BOTO3 Describe instances
            aws_client = aws_session.client('ec2')
            aws_response = aws_client.describe_instances(InstanceIds=[instance_id])
            aws_response = json.dumps(aws_response, default=_json_fallback)
            aws_response = json.loads(aws_response)
            action_result.add_data(aws_response)

            if ('Reservations' in aws_response and 'Instances' in aws_response['Reservations'][0]):
                volumes = []
                securitygroups = []
                tags = []
                vol_list = ""

                for vol in aws_response['Reservations'][0]['Instances'][0]['BlockDeviceMappings']:
                    volumes.append({'volumeid': vol['Ebs']['VolumeId'], 'volstatus': vol['Ebs']['Status'], 'volattachtime': vol['Ebs']['AttachTime']})
                    vol_list += vol['Ebs']['VolumeId'] + ", "
                total_volumes = {'total_volumes': len(volumes)}
                vol_list = vol_list[:-2]

                for secgrp in aws_response['Reservations'][0]['Instances'][0]['SecurityGroups']:
                    securitygroups.append({'secgrpid': secgrp['GroupId'], 'secgrpname': secgrp['GroupName']})
                total_secgrps = {'total_secgrps': len(securitygroups)}

                for tag in aws_response['Reservations'][0]['Instances'][0]['Tags']:
                    tags.append({'tagkey': tag['Key'], 'tagvalue': tag['Value']})
                total_tags = {'total_tags': len(tags)}

                action_result.update_summary(total_volumes)
                action_result.update_summary(total_secgrps)
                action_result.update_summary(total_tags)
                action_result.update_summary({'vol_list': vol_list})
                action_result.add_data({'volumes': volumes})
                action_result.add_data({'securitygroups': securitygroups})
                action_result.add_data({'tags': tags})

            action_result.set_status(phantom.APP_SUCCESS)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
            return action_result.get_status()

        return action_result.get_status()

    def _handle_aws_describe_user(self, param):
        # Get the config
        config = self.get_config()

        self.debug_print("param", param)

        # create an iam client object
        # client = boto3.client('iam')
        # add action_result to the app run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # get region
        region = config.get(AWS_REGION)
        aws_access_key_id = config.get(AWS_ACCESS_KEY_ID)
        aws_secret_access_key = config.get(AWS_SECRET_ACCESS_KEY)
        # get the user name
        usr_name = param[AWS_USER]

        try:
            if (region and aws_access_key_id and aws_secret_access_key):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
            elif(region and not aws_access_key_id and not aws_secret_access_key ):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region)
            else:
                action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
                return action_result.get_status

            user_dict = {}                          # user info
            groups = []
            policies = []
            roles = []
            policy_list = []                         # policy list containing both the policy name and arn
            policy_name_list = []                   # list of policy name from the
            role_list = []                          # list of role names and role ids

            # final result
            # using sessions
            aws_client = aws_session.client('iam')
            # AWS user info
            user_i = aws_client.get_user(UserName=usr_name)
            user_i = json.dumps(user_i, default=_json_fallback)
            user_i = json.loads(user_i)

            user_dict["UserName"] = user_i["User"]["UserName"]
            user_dict["UserID"] = user_i["User"]["UserId"]
            user_dict["CreateDate"] = user_i["User"]["CreateDate"]

            if "PasswordLastUsed" in user_i["User"].keys():
                user_dict["PasswordLastUsed"] = user_i["User"]["PasswordLastUsed"]

            user_i = aws_client.list_mfa_devices(UserName=usr_name)
            user_i = json.dumps(user_i, default=_json_fallback)
            user_i = json.loads(user_i)

            # checking if the user has MFA enabled
            if len(user_i["MFADevices"]) > 0:
                user_dict["MFAEnabled"] = "Yes"
            else:
                user_dict["MFAEnabled"] = "No"

            # get the list of groups for this user
            group_list = aws_client.list_groups_for_user(UserName=usr_name)
            # clean up the json file
            group_list = json.dumps(group_list, default=_json_fallback)
            group_list = json.loads(group_list)

            # get the polices per group
            for group in group_list["Groups"]:
                # collecting data on group
                new_group = {}
                new_group["GroupName"] = group["GroupName"]
                new_group["GroupId"] = group["GroupId"]
                new_group["CreateDate"] = group["CreateDate"]
                groups.append(new_group)
                # collect the list of polices per group
                group_policy = aws_client.list_attached_group_policies(GroupName=group["GroupName"])
                group_policy = json.dumps(group_policy, default=_json_fallback)
                group_policy = json.loads(group_policy)
                policy_list_per_group = group_policy["AttachedPolicies"]
                policy_list = policy_list + policy_list_per_group

            # get the roles for each policy
            for policy in policy_list:
                # Collecting data on policy
                new_policy = {}
                new_policy["PolicyName"] = policy["PolicyName"]
                policy_info = aws_client.get_policy(PolicyArn=policy["PolicyArn"])
                policy_info = json.dumps(policy_info, default=_json_fallback)
                policy_info = json.loads(policy_info)
                new_policy["PolicyId"] = policy_info["Policy"]["PolicyId"]
                new_policy["CreateDate"] = policy_info["Policy"]["CreateDate"]
                if "UpdateDate" in policy_info["Policy"].keys():
                    new_policy["UpdateDate"] = policy_info["Policy"]["UpdateDate"]
                policies.append(new_policy)
                # collecting roles
                policy_enti = aws_client.list_entities_for_policy(PolicyArn=policy["PolicyArn"])
                policy_enti = json.dumps(policy_enti, default=_json_fallback)
                policy_enti = json.loads(policy_enti)
                role_list_per_policy = policy_enti["PolicyRoles"]
                role_list = role_list + role_list_per_policy

            # get the policies per role to make sure that there isn't polices that are not captured yet
            for role in role_list:
                # collecting data on role
                new_role = {}
                new_role["RoleName"] = role["RoleName"]
                role_info = aws_client.get_role(RoleName=role["RoleName"])
                role_info = json.dumps(role_info, default=_json_fallback)
                role_info = json.loads(role_info)
                new_role["RoleId"] = role_info["Role"]["RoleId"]
                new_role["CreateDate"] = role_info["Role"]["CreateDate"]
                roles.append(new_role)
                # collect additional policies not collected
                role_policy = aws_client.list_attached_role_policies(RoleName=role["RoleName"])
                role_policy = json.dumps(role_policy, default=_json_fallback)
                role_policy = json.loads(role_policy)
                policy_name_list = policy_name_list + role_policy["AttachedPolicies"]

            # get addtional policy names from the roles
            for policy in policy_name_list:
                new_policy = {}
                policy_info = aws_client.get_policy(PolicyArn=policy["PolicyArn"])
                policy_info = json.dumps(policy_info, default=_json_fallback)
                policy_info = json.loads(policy_info)
                new_policy["PolicyName"] = policy_info["Policy"]["PolicyName"]
                new_policy["PolicyId"] = policy_info["Policy"]["PolicyId"]
                new_policy["CreateDate"] = policy_info["Policy"]["CreateDate"]
                if "UpdateDate" in policy_info["Policy"].keys():
                    new_policy["UpdateDate"] = policy_info["Policy"]["UpdateDate"]
                policies.append(new_policy)

            user_info = {}    # Part of final data
            user_info["Groups"] = groups
            # user_info["Policies"] = policies
            user_info["Policies"] = list({p["PolicyId"]: p for p in policies}.values())
            user_info["Roles"] = roles

            # use as a container
            container = {}
            container["User"] = user_dict
            container["UserInfo"] = user_info
            container = json.dumps(container, default=_json_fallback)
            container = json.loads(container)
            action_result.add_data(container)
            action_result.set_status(phantom.APP_SUCCESS)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
            return action_result.get_status

    # Detches user from autoscaling group (-Sirak)
    def _handle_aws_detach_instance_from_autoscaling_group(self, param):

        # Get the config
        config = self.get_config()
        self.debug_print("param", param)

        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # get region
        region = config.get(AWS_REGION)
        aws_access_key_id = config.get(AWS_ACCESS_KEY_ID)
        aws_secret_access_key = config.get(AWS_SECRET_ACCESS_KEY)
        instance_id = param[AWS_INSTANCE]
        autoscaling_group_name = ""

        if param.get(AWS_AUTOSCALING_GROUP_NAME):
            autoscaling_group_name = param[AWS_AUTOSCALING_GROUP_NAME]

        try:
            if (region and aws_access_key_id and aws_secret_access_key):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
            elif(region and not aws_access_key_id and not aws_secret_access_key ):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region)
            else:
                action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
                return action_result.get_status

            # AWS client instnace
            aws_client = aws_session.client('autoscaling')
            response = aws_client.describe_auto_scaling_instances(InstanceIds=[instance_id])
            if(len(response['AutoScalingInstances']) > 0):
                if(autoscaling_group_name and response['AutoScalingInstances'][0]['AutoScalingGroupName'] != autoscaling_group_name):
                    summary = {'summary': "Instance: " + instances_id + " is not conected to the Auto-scaling Group: " + autoscaling_group_name + "."}
                    action_result.update_summary(summary)
                    action_result.set_status(phantom.APP_SUCCESS)

                autoscaling_group_name = response['AutoScalingInstances'][0]['AutoScalingGroupName']
                response = aws_client.detach_instances(InstanceIds=[instance_id], AutoScalingGroupName=autoscaling_group_name, ShouldDecrementDesiredCapacity=False)
                summary = {'summary': "Detached instance: " + instance_id + " from autoscaling group: " + autoscaling_group_name + '".'}
                action_result.add_data(response)
                action_result.update_summary(summary)
                action_result.set_status(phantom.APP_SUCCESS)

            else:
                action_result.update_summary({'summary': 'No autoscaling group associated with Instance: ' + instance_id + '.'})
                action_result.set_status(phantom.APP_SUCCESS)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
            return action_result.get_status()

    # Deregister instance from clastic load balancer (-Sirak)
    def _handle_aws_deregister_instance_from_elb(self, param):

        # Get the config
        config = self.get_config()
        self.debug_print("param", param)

        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # get region, instance_id & elb_name
        region = config.get(AWS_REGION)
        aws_access_key_id = config.get(AWS_ACCESS_KEY_ID)
        aws_secret_access_key = config.get(AWS_SECRET_ACCESS_KEY)
        instance_id = param[AWS_INSTANCE]
        elb_name = ""

        if param.get(AWS_ELB_NAME):
            elb_name = param[AWS_ELB_NAME]

        try:
            if (region and aws_access_key_id and aws_secret_access_key):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
            elif(region and not aws_access_key_id and not aws_secret_access_key ):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region)
            else:
                action_result.update_summary(summary)
                action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
                return action_result.get_status

            aws_client = aws_session.client('elb')
            if(elb_name):
                response = aws_client.describe_instance_health(LoadBalancerName=elb_name, Instances=[
                            {
                                'InstanceId': instance_id
                            }
                ])
                if(len(response['InstanceStates']) < 1):
                    summary = {'summary': "Instance: " + instances_id + " is not conected to the ELB: " + elb_name + "."}
                    action_result.update_summary(summary)
                    action_result.set_status(phantom.APP_SUCCESS)
                    return action_result.get_status()

            else:
                response = aws_client.describe_load_balancers()
                elb_name = None
                for i in range(len(response['LoadBalancerDescriptions'])):
                    for j in range(len(response['LoadBalancerDescriptions'][i]['Instances'])):
                        if instance_id in response['LoadBalancerDescriptions'][i]['Instances'][j]['InstanceId']:
                            elb_name = response['LoadBalancerDescriptions'][i]['LoadBalancerName']
                if elb_name is None:
                    summary = {'summary': "Instance: " + instance_id + " is not connected to an ELB."}
                    action_result.update_summary(summary)
                    action_result.set_status(phantom.APP_SUCCESS)
                    return action_result.get_status()

            aws_client.deregister_instances_from_load_balancer(LoadBalancerName=elb_name, Instances=[
                                    {
                                        'InstanceId': instance_id
                                    }
            ])

            summary = {'summary': "De-registered instance: " + instance_id + " from ELB: " + elb_name + "."}
            action_result.add_data(response)
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
            return action_result.get_status()

    # Disables termination of the instance via API call (-Sirak)
    def _handle_aws_disable_instance_api_termination(self, param):

        # Get the config
        config = self.get_config()
        self.debug_print("param", param)

        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # get region
        region = config.get(AWS_REGION)
        aws_access_key_id = config.get(AWS_ACCESS_KEY_ID)
        aws_secret_access_key = config.get(AWS_SECRET_ACCESS_KEY)
        instance_id = param[AWS_INSTANCE]

        try:
            if (region and aws_access_key_id and aws_secret_access_key):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
            elif(region and not aws_access_key_id and not aws_secret_access_key ):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region)
            else:
                action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
                return action_result.get_status

            aws_client = aws_session.client('ec2')
            response = aws_client.modify_instance_attribute(DryRun=False, InstanceId=instance_id, Attribute='disableApiTermination', Value='true')
            summary = {'summary': "Disabled API termination for instance: " + instance_id + "."}
            action_result.add_data(response)
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
            return action_result.get_status()

    # Snapshot all volumes attached to the instacne (-Sirak)
    def _handle_aws_snapshot_volumes(self, param):
            # Get the config
            config = self.get_config()
            self.debug_print("param", param)

            # Add an action result to the App Run
            action_result = ActionResult(dict(param))
            self.add_action_result(action_result)

            # get region
            region = config.get(AWS_REGION)
            aws_access_key_id = config.get(AWS_ACCESS_KEY_ID)
            aws_secret_access_key = config.get(AWS_SECRET_ACCESS_KEY)
            attached_vols = param[AWS_ATTACHED_VOLUMES]
            attached_vols = attached_vols.split(", ")
            description = ""

            if param.get(AWS_ATTACHED_VOLUMES_DESCRIPTION):
                description = param[AWS_ATTACHED_VOLUMES_DESCRIPTION]

            try:
                if (region and aws_access_key_id and aws_secret_access_key):
                    self.save_progress("Using Region {0}".format(region))
                    aws_session = boto3.session.Session(region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
                elif(region and not aws_access_key_id and not aws_secret_access_key ):
                    self.save_progress("Using Region {0}".format(region))
                    aws_session = boto3.session.Session(region_name=region)
                else:
                    action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
                    return action_result.get_status

                aws_client = aws_session.client('ec2')
                summary = "Snapshot the following Volumes:"
                vol_response = []
                for vol in attached_vols:
                    response = aws_client.create_snapshot(DryRun=False, VolumeId=vol, Description=description)
                    response = json.dumps(response, default=_json_fallback)
                    response = json.loads(response)
                    vol_response.append(response)
                    summary += vol + ", "
                summary = {'summary': summary}
                action_result.add_data(vol_response)
                action_result.update_summary(summary)
                action_result.set_status(phantom.APP_SUCCESS)

            except Exception as e:
                action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
                return action_result.get_status()

    # Add instance to the quarantine security group (-Sirak)
    # *can be extended to add to security group
    def _handle_aws_add_to_security_group(self, param):
        # Get the config
        config = self.get_config()
        self.debug_print("param", param)

        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # get region
        region = config.get(AWS_REGION)
        aws_access_key_id = config.get(AWS_ACCESS_KEY_ID)
        aws_secret_access_key = config.get(AWS_SECRET_ACCESS_KEY)
        sg_name = param[AWS_SECURITY_GROUP_NAME]
        instance_id = param[AWS_INSTANCE]

        try:
            if (region and aws_access_key_id and aws_secret_access_key):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
            elif(region and not aws_access_key_id and not aws_secret_access_key ):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region)
            else:
                summary = {'summary': "Security group: " + sg_name + " doesn't exist."}
                action_result.update_summary(summary)
                action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
                return action_result.get_status

            aws_client = aws_session.client('ec2')
            sg_exists = False
            response = aws_client.describe_security_groups()
            existing_sgs = []

            for i in range(len(response['SecurityGroups'])):
                existing_sgs.append({response['SecurityGroups'][i]['GroupName']: response['SecurityGroups'][i]['GroupId']})

            for item in existing_sgs:
                if sg_name in item:
                    sg_id = item[sg_name]
                    sg_exists = True
                    print('Security group "' + sg_name + '" (' + sg_id + ') already exists.')
                    break

            if (sg_exists):
                response = aws_client.modify_instance_attribute(DryRun=False, InstanceId=instance_id, Groups=[sg_id])
                summary = {'summary': "The instance: " + instance_id + " has been added to the security group: " + sg_name + "."}
                action_result.add_data(response)
                action_result.update_summary(summary)
                action_result.set_status(phantom.APP_SUCCESS)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
            return action_result.get_status()

    # addes tag to the instace (-Sirak)
    def _handle_aws_add_tag(self, param):
        # Get the config
        config = self.get_config()
        self.debug_print("param", param)

        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # get region
        region = config.get(AWS_REGION)
        aws_access_key_id = config.get(AWS_ACCESS_KEY_ID)
        aws_secret_access_key = config.get(AWS_SECRET_ACCESS_KEY)
        instance_id = param[AWS_INSTANCE]
        tag_key = param[AWS_TAG_KEY]
        tag_value = param[AWS_TAG_VALUE]

        try:

            if (region and aws_access_key_id and aws_secret_access_key):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
            elif(region and not aws_access_key_id and not aws_secret_access_key ):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region)
            else:
                action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
                return action_result.get_status()

            aws_client = aws_session.client('ec2')
            response = aws_client.create_tags(DryRun=False, Resources=[instance_id], Tags=[
                {
                    'Key': tag_key,
                    'Value': tag_value
                }
            ])
            summary = {'summary': " The key: " + tag_key + " and value: " + tag_value + " has been added to the instance: " + instance_id + "."}
            action_result.add_data(response)
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
            return action_result.get_status()

    # adds a network acl rule using the network acl id (-Sirak)
    def _handle_aws_add_netwrokacl_rule(self, param):
        config = self.get_config()
        self.debug_print("parm", param)

        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # Add an action result to the app Run
        region = config.get(AWS_REGION)
        aws_access_key_id = config.get(AWS_ACCESS_KEY_ID)
        aws_secret_access_key = config.get(AWS_SECRET_ACCESS_KEY)
        network_acl_id = param[AWS_NETWORK_ACL_ID]
        # paraters for creating a rule
        egress_rule = param[AWS_EGRESS_RULE]
        ip = param[AWS_IP]
        rule_action = param[AWS_RULE_ACTION]
        rule_number = param[AWS_RULE_NUMBER]
        port_range = None
        if(param.get(AWS_PORT_RANGE)):
            ip_range = param[AWS_PORT_RANGE]
            ip_range.split("-")

        try:
            if (region and aws_access_key_id and aws_secret_access_key):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
            elif(region and not aws_access_key_id and not aws_secret_access_key ):
                self.save_progress("Using Region {0}".format(region))
                aws_session = boto3.session.Session(region_name=region)
            else:
                action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
                return action_result.get_status()

            aws_ec2 = aws_session.resources('ec2')
            aws_nacl = aws_ec2.NetworkAcl(network_acl_id)
            cidr = ip + "/32"
            summary = "Rule #" + str(rule_number) + " that " + rule_action + " " + cidr + " on port_range : "
            if(port_range is not None):
                aws_nacl.create_entry(CidrBlock=cidr, Egress=egress_rule, PortRange={
                    'From': port_range[0],
                    'To': port_range[1]
                }, Protocol='all', RuleAction=rule_action, RuleNumber=rule_number)
                summary += port_range[0] + " to " + port_range[1]
            else:
                aws_nacl.create_entry(CidrBlock=cidr, Egress=egress_rule, Protocol='all', RuleAction=rule_action, RuleNumber=rule_number)
                summary += "all"
            if egress_rule:
                summary += " on both egress and ingress has been applied."
            else:
                summary += " on ingress only has been applied."
            summary = {'summary': summary}
            aws_nacl.reload()
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR_API, e)
            return action_result.get_status()

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == self.ACTION_ID_AWS_DESCRIBE_INSTANCE):
            ret_val = self._handle_aws_describe_instance(param)

        elif (action_id == self.ACTION_ID_AWS_DESCRIBE_USER):
            ret_val = self._handle_aws_describe_user(param)

        elif (action_id == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)

        elif (action_id == self.ACTION_ID_AWS_DETACH_INSTANCE_FROM_AUTOSCALING_GROUP):
            ret_val = self._handle_aws_detach_instance_from_autoscaling_group(param)

        elif (action_id == self.ACTION_AWS_DEREGISTER_INSTANCE_FROM_ELB):
            ret_val = self._handle_aws_deregister_instance_from_elb(param)

        elif (action_id == self.ACTION_AWS_DISABLE_INSTANCE_API_TERMINATION):
            ret_val = self._handle_aws_disable_instance_api_termination(param)

        elif (action_id == self.ACTION_AWS_SNAPSHOT_VOLUMES):
            ret_val = self._handle_aws_snapshot_volumes(param)

        elif (action_id == self.ACTION_AWS_ADD_TO_SECURITY_GROUP):
            ret_val = self._handle_aws_add_to_security_group(param)

        elif (action_id == self.ACTION_AWS_ADD_TAG):
            ret_val = self._handle_aws_add_tag(param)

        elif (action_id == self.ACTION_AWS_ADD_NETWORKACL_RULE):
            ret_Val == self._handle_aws_add_netwrokacl_rule(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AWSConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
