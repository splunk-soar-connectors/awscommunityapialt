[comment]: # "Auto-generated SOAR connector documentation"
# AWS Community App 2

Publisher: Jarid Richardson and Joseph Sirak  
Connector Version: 1\.0\.2  
Product Vendor: Amazon  
Product Name: AWS  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.2\.7532  

Implements investigation and containment by integrating with the AWS API

[comment]: # "File: readme.md"
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
This app contains actions that are a modeled off of Amazons best practices for instance containment.

Per amazon the order for isolation, and for reference with playbook development is:

1.  Describe Instance
2.  Detach instance from Auto-Scaling group
3.  Deregister instance from ELB Group
4.  Add instance to a containment security group (info on security group below)
5.  Disable instance API termination
6.  Snapshot volumes
7.  Add quarantine tag

### AWS Containment Security Group

Create an EC2 Security group in AWS with an empty ruleset. AWS automatically has an implied disallow
rule, so as long as no IP is provided, it will cut off all communication. It is best practice to add
the IP address for your Forensic Investion Instance to the inbound rules.

### AWS Role for Phantom Actions

In order for all of actions to run successfully, please add an IAM role with the following
permissions:

      
        {
          "Version": "2012-10-17",
          "Statement": [
          {
             "Sid": "Stmt1433358496000",
              "Effect": "Allow",
              "Action": [
                  "ec2:AttachVolume",
                  "ec2:AuthorizeSecurityGroupEgress",
                  "ec2:AuthorizeSecurityGroupIngress",
                  "ec2:CopySnapshot",
                  "ec2:CreateSecurityGroup",
                  "ec2:CreateSnapshot",
                  "ec2:CreateTags",
                  "ec2:CreateVolume",
                  "ec2:DescribeInstances",
                  "ec2:DescribeSecurityGroups",
                  "ec2:DescribeSnapshots",
                  "ec2:DescribeVolumes",
                  "ec2:GetConsoleOutput",
                  "ec2:ModifyInstanceAttribute",
                  "ec2:ModifyNetworkInterfaceAttribute",
                  "ec2:RevokeSecurityGroupEgress",
                  "iam:GetUser",
                  "autoscaling:DescribeAutoScalingGroups",
                  "autoscaling:DetachInstances"
              ],
              "Resource": [
                  "*"
              ]
          }]
        }
      


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a AWS asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**region** |  required  | string | AWS Region
**aws\_access\_key\_id** |  required  | password | AWS Access Key ID
**aws\_secret\_access\_key** |  required  | password | AWS Secret Access Key
**forensics\_machine** |  optional  | string | Forensics Machine Instance ID

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[describe instance](#action-describe-instance) - Describes one or more of your instances  
[list users](#action-list-users) - Lists users and roles  
[detach instance](#action-detach-instance) - Detaches an instance from an autoscaling group  
[deregister instance](#action-deregister-instance) - Deregister instance from AWS Elastic Load Balance  
[disable instance termination](#action-disable-instance-termination) - Disable the instance from being terminated via API  
[snapshot volumes](#action-snapshot-volumes) - Snapshots all volumes attached to the instance  
[add security group](#action-add-security-group) - Adds the instance to a security group  
[add tag](#action-add-tag) - Adds tag to instances  
[add acl](#action-add-acl) - Add a NetworkAcl rule  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'describe instance'
Describes one or more of your instances

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**instance** |  required  | Instance ID | string |  `aws ge instance id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.instance | string |  `aws ge instance id` 
action\_result\.data | string | 
action\_result\.summary\.total\_secgrps | string | 
action\_result\.summary\.total\_tags | string | 
action\_result\.summary\.total\_volumes | string | 
action\_result\.summary\.vol\_list | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list users'
Lists users and roles

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user** |  required  | User Name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.user | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detach instance'
Detaches an instance from an autoscaling group

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**instance** |  required  | Instance ID | string |  `aws ge instance id` 
**autoscaling\_group\_name** |  optional  | Auto\-Scaling Group Name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.autoscaling\_group\_name | string | 
action\_result\.parameter\.instance | string |  `aws ge instance id` 
action\_result\.data | string | 
action\_result\.summary\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'deregister instance'
Deregister instance from AWS Elastic Load Balance

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**instance** |  required  | Instance ID | string |  `aws ge instance id` 
**elb\_name** |  optional  | Elastic Load Balancer Name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.elb\_name | string | 
action\_result\.parameter\.instance | string |  `aws ge instance id` 
action\_result\.data | string | 
action\_result\.summary\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'disable instance termination'
Disable the instance from being terminated via API

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**instance** |  required  | Instance ID | string |  `aws ge instance id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.instance | string |  `aws ge instance id` 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.content\-type | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.date | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.server | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.transfer\-encoding | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.vary | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPStatusCode | numeric | 
action\_result\.data\.\*\.ResponseMetadata\.RequestId | string | 
action\_result\.data\.\*\.ResponseMetadata\.RetryAttempts | numeric | 
action\_result\.summary\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'snapshot volumes'
Snapshots all volumes attached to the instance

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**attached\_vols** |  required  | List of attached volume IDs | string | 
**description** |  optional  | Description for snapshot | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.attached\_vols | string | 
action\_result\.parameter\.description | string | 
action\_result\.data\.\*\.Description | string | 
action\_result\.data\.\*\.Encrypted | boolean | 
action\_result\.data\.\*\.OwnerId | string | 
action\_result\.data\.\*\.Progress | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.content\-type | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.date | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.server | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.transfer\-encoding | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.vary | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPStatusCode | numeric | 
action\_result\.data\.\*\.ResponseMetadata\.RequestId | string | 
action\_result\.data\.\*\.ResponseMetadata\.RetryAttempts | numeric | 
action\_result\.data\.\*\.SnapshotId | string | 
action\_result\.data\.\*\.StartTime | string | 
action\_result\.data\.\*\.State | string | 
action\_result\.data\.\*\.VolumeId | string | 
action\_result\.data\.\*\.VolumeSize | numeric | 
action\_result\.summary\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add security group'
Adds the instance to a security group

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sg\_name** |  required  | Security group name | string | 
**instance** |  required  | Instance ID | string |  `aws ge instance id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.instance | string |  `aws ge instance id` 
action\_result\.parameter\.sg\_name | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.content\-type | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.date | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.server | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.transfer\-encoding | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.vary | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPStatusCode | numeric | 
action\_result\.data\.\*\.ResponseMetadata\.RequestId | string | 
action\_result\.data\.\*\.ResponseMetadata\.RetryAttempts | numeric | 
action\_result\.summary\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add tag'
Adds tag to instances

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**tag\_key** |  required  | Tag Key | string | 
**tag\_value** |  required  | Tag Value | string | 
**instance** |  required  | Instance ID | string |  `aws ge instance id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.instance | string |  `aws ge instance id` 
action\_result\.parameter\.tag\_key | string | 
action\_result\.parameter\.tag\_value | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.content\-type | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.date | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.server | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.transfer\-encoding | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPHeaders\.vary | string | 
action\_result\.data\.\*\.ResponseMetadata\.HTTPStatusCode | numeric | 
action\_result\.data\.\*\.ResponseMetadata\.RequestId | string | 
action\_result\.data\.\*\.ResponseMetadata\.RetryAttempts | numeric | 
action\_result\.summary\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add acl'
Add a NetworkAcl rule

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**network\_acl\_id** |  required  | Network Acl Id | string | 
**egress\_rule** |  required  | Is Egress Rule\. \(True/False\) | boolean | 
**ip** |  required  | IP Address | string |  `ip` 
**rule\_action** |  required  | Rule Action \(allow/deny\) | string | 
**rule\_number** |  required  | Rule Number | numeric | 
**port\_range** |  optional  | Port Range \(Ex\. 120\-6000\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.egress\_rule | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.network\_acl\_id | string | 
action\_result\.parameter\.port\_range | string | 
action\_result\.parameter\.rule\_action | string | 
action\_result\.parameter\.rule\_number | numeric | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 