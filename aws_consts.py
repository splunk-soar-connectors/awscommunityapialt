# --
# File: samplewhois_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

AWS_REGION = "region"
AWS_FORENSIC_MACHINE = "forensics_machine"

# input aws access key id (-Sirak)
AWS_ACCESS_KEY_ID = "aws_access_key_id"
AWS_SECRET_ACCESS_KEY = "aws_secret_access_key"

AWS_INSTANCE = "instance"
AWS_INSTANCE_SCREENSHOT = "screenshot"
AWS_INSTANCE_CONSOLE_OUTPUT = "consoleOutput"

# input user name (-Sirak)
AWS_USER = "user"

# input Auto Scaling Group name (-Sirak)
AWS_AUTOSCALING_GROUP_NAME = "autoscaling_group_name"

# input ELB name (-Sirak)
AWS_ELB_NAME = "elb_name"

# input for snapshot volumes (-Sirak)
AWS_ATTACHED_VOLUMES_DESCRIPTION = "description"
AWS_ATTACHED_VOL_COUNT = "attached_vol_count"
AWS_ATTACHED_VOLUMES = "attached_vols"

# input to setup quarantine security group (-Sirak)
AWS_VPC_ID = "vpc_id"
AWS_SECURITY_GROUP_NAME = "sg_name"

# input for creating tags
AWS_TAG_KEY = "tag_key"
AWS_TAG_VALUE = "tag_value"

AWS_ERR_REGION = "No Region Specified, API Call failed"
AWS_ERR_API = "An error occured when requesting data"
AWS_SUCC_API = "API Queried successfully"
AWS_ERR_API_CONNECTION = "Connection to API failed"
AWS_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
AWS_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"


# input for the Network ACL (-Sirak)
AWS_EGRESS_RULE = "egress_rule"
AWS_PORT_RANGE = "port_range"
AWS_NETWORK_ACL_ID = "network_acl_id"
AWS_IP = "ip"
AWS_RULE_ACTION = "rule_action"
AWS_RULE_NUMBER = "rule_number"
