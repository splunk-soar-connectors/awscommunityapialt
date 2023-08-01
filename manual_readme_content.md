[comment]: # "File: README.md"
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
      
