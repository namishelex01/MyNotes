S3
Monitoring of S3 Buckets which have FULL CONTROL for Authenticated Group.
Monitoring of S3 buckets which have FULL CONTROL for ALL Users group.
Monitoring of S3 buckets which have default encryption disabled
Monitoring of S3 buckets which have provided READ access to the Authenticated Group
Monitoring of S3 buckets which have provided READ access to the All Users Group
Monitoring of S3 buckets which have provided Write Access to the Authenticated Group
Monitoring of S3 buckets which have provided Write Access to the All Users Group
Monitoring of S3 buckets which have provided READ_ACP access to the Authenticated Group
Monitoring of S3 buckets which have provided READ_ACP access to the All Users Group
Monitoring of S3 buckets which have provided Write_ACP Access to the Authenticated Group
Monitoring of S3 buckets which have provided Write_ACP Access to the All Users Group
Monitoring of S3 buckets to ensure if SSL/TLS is enabled for securing data in transit
Monitoring of S3 buckets to ensure if logging is enabled or not
Monitoring of S3 buckets to ensure if bucket versioning is enabled or not.
Monitoring of S3 buckets to ensure that MFA is enabled for bucket delete operation.

IAM
Monitoring to check if the Root Account has MFA enabled or not.
Monitoring to check if Users Account has MFA enabled or not.
Monitoring to check if Password is set to ‘Not Expire.’
Monitoring to check if password reuse is enabled or not.
Monitoring to check if the password policy is weak or not.
Monitoring to check if root account has active keys associated with the account.
Monitoring to check if root account if recently used.
Monitoring to check if there is no key(both active & inactive) rotation.
Monitoring to check if Users has inline policies setup instead of Managed Group and Role policies
Monitoring to check for inactive IAM users, unused IAM users.
Monitoring to check for policies with NotAction attribute setup.
Monitoring to check if access keys are rotated or not.
Monitoring to check if IAM SSH keys are rotated or not.

CloudTrail
Monitoring of AWS Accounts where CloudTrail is disabled.
Monitoring to ensure if Cloud Trail is enabled for global services like STS, IAM, and CloudFront.
Monitoring to ensure if Cloud Trail log file integration validity is enabled or not.
Monitoring to check if CloudTrail is enabled but logging for a trail is disabled
Monitoring to ensure if bucket to which CloudAware is logging is not publicly accessible.
Monitoring to check if CloudTrail log files are encrypted or not.
Monitoring to check if Trail is enabled for all regions or not.

VPC
Monitoring of AWS VPC to ensure that no network ACL exist which allow ingress traffic from all ports.
Monitoring of AWS VPC to ensure that no network ACL exist which allow egress traffic to all ports.
Monitoring of AWS VPC to find out unused virtual private gateways.
Monitoring of AWS VPC to find out if any VPC endpoint is exposed by checking for the principal value in the policy.
Monitoring of AWS VPC to find out if Flow Logs have been enabled or not for VPC.

EC2
Monitoring of AWS EC2 to ensure they are not using any blacklisted AMIs
Monitoring of AWS EC2 to ensure they do not have any default security group.
Monitoring of AWS EC2 to ensure that there is no Security Group with unrestricted outbound access.
Monitoring of AWS EC2 to ensure that there is no unrestricted inbound access to following services
FTP
MSSql
MySql
MongoDB
SMTP
Telnet
SSH
NetBIOS access etc.
Monitoring of AWS EC2 to ensure that unused EC2 keypairs are decommissioned.

ELB
Monitoring of AWS ELB to ensure that no insecure protocols or ciphers deployed. This is generally decided by organization per their current compatibility and security standards which should be followed by best practices such as ‘Server Order Preference.’
Monitoring of AWS ELB to ensure that they have a valid Security Group associated with it.
Monitoring of AWS ELB to ensure that they have latest security policies deployed.
Monitoring of AWS EBS to ensure that it is encrypted.
Monitoring of AWS ELB to ensure that they are encrypted with KMS CMKs to have full control over keys.
Monitoring of AWS ELB to ensure that the EBS snapshots are not publicly available.
Monitoring of AWS ELB to ensure that the EBS snapshot is also encrypted.

RDS
Monitoring of AWS RDS to ensure that the DB security groups do not allow unrestricted inbound access. It should be noted that DB security groups were possible for EC2 classic instances before 04/12/2013. After that date, only EC2-VPC instances are supported which in turn use VPC Security Groups.
Monitoring of AWS RDS to ensure that auto minor version feature is enabled.
Monitoring of AWS RDS to ensure that the RDS instances are encrypted.
Monitoring of AWS RDS to ensure that RDS instances are encrypted using KMS CMK’s to have full control
Monitoring of AWS RDS to ensure that the RDS instances are not publicly accessible.
Monitoring of AWS RDS to ensure that RDS snapshots are not publicly accessible
Monitoring of AWS RDS to ensure that RDS snapshots are encrypted.

Redshift
Monitoring of AWS RDS to ensure that Redshift clusters are encrypted.
Monitoring of AWS RDS to ensure that Encrypted Redshift clusters are using KMS CMK’s for full control
Monitoring of AWS RDS to ensure that Redshift clusters are not publicly available.
Monitoring of AWS RDS to ensure that activity logging is enabled.
Monitoring of AWS RDS to ensure that Redshift clusters are launched within VPC.
