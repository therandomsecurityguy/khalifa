

# CIS AWS Foundations Benchmark in Security Hub CSPM
<a name="cis-aws-foundations-benchmark"></a>

The Center for Internet Security (CIS) AWS Foundations Benchmark serves as a set of security configuration best practices for AWS. These industry-accepted best practices provide you with clear, step-by-step implementation and assessment procedures. Ranging from operating systems to cloud services and network devices, the controls in this benchmark help you protect the specific systems that your organization uses. 

AWS Security Hub CSPM supports CIS AWS Foundations Benchmark versions 5.0.0, 3.0.0, 1.4.0, and 1.2.0. This page lists the security controls that each version supports. It also provides a comparison of the versions.

## CIS AWS Foundations Benchmark version 5.0.0
<a name="cis5v0-standard"></a>

Security Hub CSPM supports version 5.0.0 (v5.0.0) of the CIS AWS Foundations Benchmark. Security Hub CSPM has satisfied the requirements of CIS Security Software Certification and has been awarded CIS Security Software Certification for the following CIS Benchmarks: 
+ CIS Benchmark for CIS AWS Foundations Benchmark, v5.0.0, Level 1
+ CIS Benchmark for CIS AWS Foundations Benchmark, v5.0.0, Level 2

### Controls that apply to CIS AWS Foundations Benchmark version 5.0.0
<a name="cis5v0-controls"></a>

[[Account.1] Security contact information should be provided for an AWS account](account-controls.md#account-1)

[[CloudTrail.1] CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events](cloudtrail-controls.md#cloudtrail-1)

[[CloudTrail.2] CloudTrail should have encryption at-rest enabled](cloudtrail-controls.md#cloudtrail-2)

[[CloudTrail.4] CloudTrail log file validation should be enabled](cloudtrail-controls.md#cloudtrail-4)

[[CloudTrail.7] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket](cloudtrail-controls.md#cloudtrail-7)

[[Config.1] AWS Config should be enabled and use the service-linked role for resource recording](config-controls.md#config-1)

[[EC2.2] VPC default security groups should not allow inbound or outbound traffic](ec2-controls.md#ec2-2)

[[EC2.6] VPC flow logging should be enabled in all VPCs](ec2-controls.md#ec2-6)

[[EC2.7] EBS default encryption should be enabled](ec2-controls.md#ec2-7)

[[EC2.8] EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)](ec2-controls.md#ec2-8)

[[EC2.21] Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389](ec2-controls.md#ec2-21)

[[EC2.53] EC2 security groups should not allow ingress from 0.0.0.0/0 to remote server administration ports](ec2-controls.md#ec2-53)

[[EC2.54] EC2 security groups should not allow ingress from ::/0 to remote server administration ports](ec2-controls.md#ec2-54)

[[EFS.1] Elastic File System should be configured to encrypt file data at-rest using AWS KMS](efs-controls.md#efs-1)

[[EFS.8] EFS file systems should be encrypted at rest](efs-controls.md#efs-8)

[[IAM.2] IAM users should not have IAM policies attached](iam-controls.md#iam-2)

[[IAM.3] IAM users' access keys should be rotated every 90 days or less](iam-controls.md#iam-3)

[[IAM.4] IAM root user access key should not exist](iam-controls.md#iam-4)

[[IAM.5] MFA should be enabled for all IAM users that have a console password](iam-controls.md#iam-5)

[[IAM.6] Hardware MFA should be enabled for the root user](iam-controls.md#iam-6)

[[IAM.9] MFA should be enabled for the root user](iam-controls.md#iam-9)

[[IAM.15] Ensure IAM password policy requires minimum password length of 14 or greater](iam-controls.md#iam-15)

[[IAM.16] Ensure IAM password policy prevents password reuse](iam-controls.md#iam-16)

[[IAM.18] Ensure a support role has been created to manage incidents with AWS Support](iam-controls.md#iam-18)

[[IAM.22] IAM user credentials unused for 45 days should be removed](iam-controls.md#iam-22)

[[IAM.26] Expired SSL/TLS certificates managed in IAM should be removed](iam-controls.md#iam-26)

[[IAM.27] IAM identities should not have the AWSCloudShellFullAccess policy attached](iam-controls.md#iam-27)

[[IAM.28] IAM Access Analyzer external access analyzer should be enabled](iam-controls.md#iam-28)

[[KMS.4] AWS KMS key rotation should be enabled](kms-controls.md#kms-4)

[[RDS.2] RDS DB Instances should prohibit public access, as determined by the PubliclyAccessible configuration](rds-controls.md#rds-2)

[[RDS.3] RDS DB instances should have encryption at-rest enabled](rds-controls.md#rds-3)

[[RDS.5] RDS DB instances should be configured with multiple Availability Zones](rds-controls.md#rds-5)

[[RDS.13] RDS automatic minor version upgrades should be enabled](rds-controls.md#rds-13)

[[RDS.15] RDS DB clusters should be configured for multiple Availability Zones](rds-controls.md#rds-15)

[[S3.1] S3 general purpose buckets should have block public access settings enabled](s3-controls.md#s3-1)

[[S3.5] S3 general purpose buckets should require requests to use TLS](s3-controls.md#s3-5)

[[S3.8] S3 general purpose buckets should block public access](s3-controls.md#s3-8)

[[S3.20] S3 general purpose buckets should have MFA delete enabled](s3-controls.md#s3-20)

[[S3.22] S3 general purpose buckets should log object-level write events](s3-controls.md#s3-22)

[[S3.23] S3 general purpose buckets should log object-level read events](s3-controls.md#s3-23)

## CIS AWS Foundations Benchmark version 3.0.0
<a name="cis3v0-standard"></a>

Security Hub CSPM supports version 3.0.0 (v3.0.0) of the CIS AWS Foundations Benchmark. Security Hub CSPM has satisfied the requirements of CIS Security Software Certification and has been awarded CIS Security Software Certification for the following CIS Benchmarks: 
+ CIS Benchmark for CIS AWS Foundations Benchmark, v3.0.0, Level 1
+ CIS Benchmark for CIS AWS Foundations Benchmark, v3.0.0, Level 2

### Controls that apply to CIS AWS Foundations Benchmark version 3.0.0
<a name="cis3v0-controls"></a>

[[Account.1] Security contact information should be provided for an AWS account](account-controls.md#account-1)

[[CloudTrail.1] CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events](cloudtrail-controls.md#cloudtrail-1)

[[CloudTrail.2] CloudTrail should have encryption at-rest enabled](cloudtrail-controls.md#cloudtrail-2)

[[CloudTrail.4] CloudTrail log file validation should be enabled](cloudtrail-controls.md#cloudtrail-4)

[[CloudTrail.7] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket](cloudtrail-controls.md#cloudtrail-7)

[[Config.1] AWS Config should be enabled and use the service-linked role for resource recording](config-controls.md#config-1)

[[EC2.2] VPC default security groups should not allow inbound or outbound traffic](ec2-controls.md#ec2-2)

[[EC2.6] VPC flow logging should be enabled in all VPCs](ec2-controls.md#ec2-6)

[[EC2.7] EBS default encryption should be enabled](ec2-controls.md#ec2-7)

[[EC2.8] EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)](ec2-controls.md#ec2-8)

[[EC2.21] Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389](ec2-controls.md#ec2-21)

[[EC2.53] EC2 security groups should not allow ingress from 0.0.0.0/0 to remote server administration ports](ec2-controls.md#ec2-53)

[[EC2.54] EC2 security groups should not allow ingress from ::/0 to remote server administration ports](ec2-controls.md#ec2-54)

[[EFS.1] Elastic File System should be configured to encrypt file data at-rest using AWS KMS](efs-controls.md#efs-1)

[[IAM.2] IAM users should not have IAM policies attached](iam-controls.md#iam-2)

[[IAM.3] IAM users' access keys should be rotated every 90 days or less](iam-controls.md#iam-3)

[[IAM.4] IAM root user access key should not exist](iam-controls.md#iam-4)

[[IAM.5] MFA should be enabled for all IAM users that have a console password](iam-controls.md#iam-5)

[[IAM.6] Hardware MFA should be enabled for the root user](iam-controls.md#iam-6)

[[IAM.9] MFA should be enabled for the root user](iam-controls.md#iam-9)

[[IAM.15] Ensure IAM password policy requires minimum password length of 14 or greater](iam-controls.md#iam-15)

[[IAM.16] Ensure IAM password policy prevents password reuse](iam-controls.md#iam-16)

[[IAM.18] Ensure a support role has been created to manage incidents with AWS Support](iam-controls.md#iam-18)

[[IAM.22] IAM user credentials unused for 45 days should be removed](iam-controls.md#iam-22)

[[IAM.26] Expired SSL/TLS certificates managed in IAM should be removed](iam-controls.md#iam-26)

[[IAM.27] IAM identities should not have the AWSCloudShellFullAccess policy attached](iam-controls.md#iam-27)

[[IAM.28] IAM Access Analyzer external access analyzer should be enabled](iam-controls.md#iam-28)

[[KMS.4] AWS KMS key rotation should be enabled](kms-controls.md#kms-4)

[[RDS.2] RDS DB Instances should prohibit public access, as determined by the PubliclyAccessible configuration](rds-controls.md#rds-2)

[[RDS.3] RDS DB instances should have encryption at-rest enabled](rds-controls.md#rds-3)

[[RDS.13] RDS automatic minor version upgrades should be enabled](rds-controls.md#rds-13)

[[S3.1] S3 general purpose buckets should have block public access settings enabled](s3-controls.md#s3-1)

[[S3.5] S3 general purpose buckets should require requests to use TLS](s3-controls.md#s3-5)

[[S3.8] S3 general purpose buckets should block public access](s3-controls.md#s3-8)

[[S3.20] S3 general purpose buckets should have MFA delete enabled](s3-controls.md#s3-20)

[[S3.22] S3 general purpose buckets should log object-level write events](s3-controls.md#s3-22)

[[S3.23] S3 general purpose buckets should log object-level read events](s3-controls.md#s3-23)

## CIS AWS Foundations Benchmark version 1.4.0
<a name="cis1v4-standard"></a>

Security Hub CSPM supports version 1.4.0 (v1.4.0) of the CIS AWS Foundations Benchmark.

### Controls that apply to CIS AWS Foundations Benchmark version 1.4.0
<a name="cis1v4-controls"></a>

 [[CloudTrail.1] CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events](cloudtrail-controls.md#cloudtrail-1) 

 [[CloudTrail.2] CloudTrail should have encryption at-rest enabled](cloudtrail-controls.md#cloudtrail-2) 

 [[CloudTrail.4] CloudTrail log file validation should be enabled](cloudtrail-controls.md#cloudtrail-4) 

 [[CloudTrail.5] CloudTrail trails should be integrated with Amazon CloudWatch Logs](cloudtrail-controls.md#cloudtrail-5) 

 [[CloudTrail.6] Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible](cloudtrail-controls.md#cloudtrail-6) 

 [[CloudTrail.7] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket](cloudtrail-controls.md#cloudtrail-7) 

 [[CloudWatch.1] A log metric filter and alarm should exist for usage of the "root" user](cloudwatch-controls.md#cloudwatch-1) 

 [[CloudWatch.4] Ensure a log metric filter and alarm exist for IAM policy changes](cloudwatch-controls.md#cloudwatch-4) 

 [[CloudWatch.5] Ensure a log metric filter and alarm exist for CloudTrail configuration changes](cloudwatch-controls.md#cloudwatch-5) 

 [[CloudWatch.6] Ensure a log metric filter and alarm exist for AWS Management Console authentication failures](cloudwatch-controls.md#cloudwatch-6) 

 [[CloudWatch.7] Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer managed keys](cloudwatch-controls.md#cloudwatch-7) 

 [[CloudWatch.8] Ensure a log metric filter and alarm exist for S3 bucket policy changes](cloudwatch-controls.md#cloudwatch-8) 

 [[CloudWatch.9] Ensure a log metric filter and alarm exist for AWS Config configuration changes](cloudwatch-controls.md#cloudwatch-9) 

 [[CloudWatch.10] Ensure a log metric filter and alarm exist for security group changes](cloudwatch-controls.md#cloudwatch-10) 

 [[CloudWatch.11] Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)](cloudwatch-controls.md#cloudwatch-11) 

 [[CloudWatch.12] Ensure a log metric filter and alarm exist for changes to network gateways](cloudwatch-controls.md#cloudwatch-12) 

 [[CloudWatch.13] Ensure a log metric filter and alarm exist for route table changes](cloudwatch-controls.md#cloudwatch-13) 

 [[CloudWatch.14] Ensure a log metric filter and alarm exist for VPC changes](cloudwatch-controls.md#cloudwatch-14) 

 [[Config.1] AWS Config should be enabled and use the service-linked role for resource recording](config-controls.md#config-1) 

 [[EC2.2] VPC default security groups should not allow inbound or outbound traffic](ec2-controls.md#ec2-2) 

 [[EC2.6] VPC flow logging should be enabled in all VPCs](ec2-controls.md#ec2-6) 

 [[EC2.7] EBS default encryption should be enabled](ec2-controls.md#ec2-7) 

 [[EC2.21] Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389](ec2-controls.md#ec2-21) 

 [[IAM.1] IAM policies should not allow full "\*" administrative privileges](iam-controls.md#iam-1) 

 [[IAM.3] IAM users' access keys should be rotated every 90 days or less](iam-controls.md#iam-3) 

 [[IAM.4] IAM root user access key should not exist](iam-controls.md#iam-4) 

 [[IAM.5] MFA should be enabled for all IAM users that have a console password](iam-controls.md#iam-5) 

 [[IAM.6] Hardware MFA should be enabled for the root user](iam-controls.md#iam-6) 

 [[IAM.9] MFA should be enabled for the root user](iam-controls.md#iam-9) 

 [[IAM.15] Ensure IAM password policy requires minimum password length of 14 or greater](iam-controls.md#iam-15) 

 [[IAM.16] Ensure IAM password policy prevents password reuse](iam-controls.md#iam-16) 

 [[IAM.18] Ensure a support role has been created to manage incidents with AWS Support](iam-controls.md#iam-18) 

 [[IAM.22] IAM user credentials unused for 45 days should be removed](iam-controls.md#iam-22) 

 [[KMS.4] AWS KMS key rotation should be enabled](kms-controls.md#kms-4) 

 [[RDS.3] RDS DB instances should have encryption at-rest enabled](rds-controls.md#rds-3) 

 [[S3.1] S3 general purpose buckets should have block public access settings enabled](s3-controls.md#s3-1) 

 [[S3.5] S3 general purpose buckets should require requests to use TLS](s3-controls.md#s3-5) 

 [[S3.8] S3 general purpose buckets should block public access](s3-controls.md#s3-8) 

 [[S3.20] S3 general purpose buckets should have MFA delete enabled](s3-controls.md#s3-20) 

## CIS AWS Foundations Benchmark version 1.2.0
<a name="cis1v2-standard"></a>

Security Hub CSPM supports version 1.2.0 (v1.2.0) of the CIS AWS Foundations Benchmark. Security Hub CSPM has satisfied the requirements of CIS Security Software Certification and has been awarded CIS Security Software Certification for the following CIS Benchmarks: 
+ CIS Benchmark for CIS AWS Foundations Benchmark, v1.2.0, Level 1
+ CIS Benchmark for CIS AWS Foundations Benchmark, v1.2.0, Level 2

### Controls that apply to CIS AWS Foundations Benchmark version 1.2.0
<a name="cis1v2-controls"></a>

 [[CloudTrail.1] CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events](cloudtrail-controls.md#cloudtrail-1) 

 [[CloudTrail.2] CloudTrail should have encryption at-rest enabled](cloudtrail-controls.md#cloudtrail-2) 

 [[CloudTrail.4] CloudTrail log file validation should be enabled](cloudtrail-controls.md#cloudtrail-4) 

 [[CloudTrail.5] CloudTrail trails should be integrated with Amazon CloudWatch Logs](cloudtrail-controls.md#cloudtrail-5) 

 [[CloudTrail.6] Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible](cloudtrail-controls.md#cloudtrail-6) 

 [[CloudTrail.7] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket](cloudtrail-controls.md#cloudtrail-7) 

 [[CloudWatch.1] A log metric filter and alarm should exist for usage of the "root" user](cloudwatch-controls.md#cloudwatch-1) 

 [[CloudWatch.2] Ensure a log metric filter and alarm exist for unauthorized API calls](cloudwatch-controls.md#cloudwatch-2) 

 [[CloudWatch.3] Ensure a log metric filter and alarm exist for Management Console sign-in without MFA](cloudwatch-controls.md#cloudwatch-3) 

 [[CloudWatch.4] Ensure a log metric filter and alarm exist for IAM policy changes](cloudwatch-controls.md#cloudwatch-4) 

 [[CloudWatch.5] Ensure a log metric filter and alarm exist for CloudTrail configuration changes](cloudwatch-controls.md#cloudwatch-5) 

 [[CloudWatch.6] Ensure a log metric filter and alarm exist for AWS Management Console authentication failures](cloudwatch-controls.md#cloudwatch-6) 

 [[CloudWatch.7] Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer managed keys](cloudwatch-controls.md#cloudwatch-7) 

 [[CloudWatch.8] Ensure a log metric filter and alarm exist for S3 bucket policy changes](cloudwatch-controls.md#cloudwatch-8) 

 [[CloudWatch.9] Ensure a log metric filter and alarm exist for AWS Config configuration changes](cloudwatch-controls.md#cloudwatch-9) 

 [[CloudWatch.10] Ensure a log metric filter and alarm exist for security group changes](cloudwatch-controls.md#cloudwatch-10) 

 [[CloudWatch.11] Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)](cloudwatch-controls.md#cloudwatch-11) 

 [[CloudWatch.12] Ensure a log metric filter and alarm exist for changes to network gateways](cloudwatch-controls.md#cloudwatch-12) 

 [[CloudWatch.13] Ensure a log metric filter and alarm exist for route table changes](cloudwatch-controls.md#cloudwatch-13) 

 [[CloudWatch.14] Ensure a log metric filter and alarm exist for VPC changes](cloudwatch-controls.md#cloudwatch-14) 

 [[Config.1] AWS Config should be enabled and use the service-linked role for resource recording](config-controls.md#config-1) 

 [[EC2.2] VPC default security groups should not allow inbound or outbound traffic](ec2-controls.md#ec2-2) 

 [[EC2.6] VPC flow logging should be enabled in all VPCs](ec2-controls.md#ec2-6) 

 [[EC2.13] Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 22](ec2-controls.md#ec2-13) 

 [[EC2.14] Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 3389](ec2-controls.md#ec2-14) 

 [[IAM.1] IAM policies should not allow full "\*" administrative privileges](iam-controls.md#iam-1) 

 [[IAM.2] IAM users should not have IAM policies attached](iam-controls.md#iam-2) 

 [[IAM.3] IAM users' access keys should be rotated every 90 days or less](iam-controls.md#iam-3) 

 [[IAM.4] IAM root user access key should not exist](iam-controls.md#iam-4) 

 [[IAM.5] MFA should be enabled for all IAM users that have a console password](iam-controls.md#iam-5) 

 [[IAM.6] Hardware MFA should be enabled for the root user](iam-controls.md#iam-6) 

 [[IAM.8] Unused IAM user credentials should be removed](iam-controls.md#iam-8) 

 [[IAM.9] MFA should be enabled for the root user](iam-controls.md#iam-9) 

 [[IAM.11] Ensure IAM password policy requires at least one uppercase letter](iam-controls.md#iam-11) 

 [[IAM.12] Ensure IAM password policy requires at least one lowercase letter](iam-controls.md#iam-12) 

 [[IAM.13] Ensure IAM password policy requires at least one symbol](iam-controls.md#iam-13) 

 [[IAM.14] Ensure IAM password policy requires at least one number](iam-controls.md#iam-14) 

 [[IAM.15] Ensure IAM password policy requires minimum password length of 14 or greater](iam-controls.md#iam-15) 

 [[IAM.16] Ensure IAM password policy prevents password reuse](iam-controls.md#iam-16) 

 [[IAM.17] Ensure IAM password policy expires passwords within 90 days or less](iam-controls.md#iam-17) 

 [[IAM.18] Ensure a support role has been created to manage incidents with AWS Support](iam-controls.md#iam-18) 

 [[KMS.4] AWS KMS key rotation should be enabled](kms-controls.md#kms-4) 

## Version comparison for CIS AWS Foundations Benchmark
<a name="cis1.4-vs-cis1.2"></a>

This section summarizes the differences between specific versions of the Center for Internet Security (CIS) AWS Foundations Benchmark—v5.0.0, v3.0.0, v1.4.0, and v1.2.0. AWS Security Hub CSPM supports each of these versions of the CIS AWS Foundations Benchmark. However, we recommend using v5.0.0 to stay current with security best practices. You can have multiple versions of CIS AWS Foundations Benchmark standards enabled at the same time. For information about enabling standards, see [Enabling a security standard](enable-standards.md). If you want to upgrade to v5.0.0, enable it before you disable an older version. This prevents gaps in your security checks. If you use the Security Hub CSPM integration with AWS Organizations and want to batch enable v5.0.0 in multiple accounts, we recommend using [central configuration](central-configuration-intro.md).

### Mapping of controls to CIS requirements in each version
<a name="cis-version-comparison"></a>

Understand which controls each version of the CIS AWS Foundations Benchmark supports.


| Control ID and title | CIS v5.0.0 requirement | CIS v3.0.0 requirement | CIS v1.4.0 requirement | CIS v1.2.0 requirement | 
| --- | --- | --- | --- | --- | 
| [[Account.1] Security contact information should be provided for an AWS account](account-controls.md#account-1) | 1.2 | 1.2 | 1.2 | 1.18 | 
| [[CloudTrail.1] CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events](cloudtrail-controls.md#cloudtrail-1) | 3.1 | 3.1 | 3.1 | 2.1 | 
| [[CloudTrail.2] CloudTrail should have encryption at-rest enabled](cloudtrail-controls.md#cloudtrail-2) | 3.5 | 3.5 | 3.7 | 2.7 | 
| [[CloudTrail.4] CloudTrail log file validation should be enabled](cloudtrail-controls.md#cloudtrail-4) | 3.2 | 3.2 | 3.2 | 2.2 | 
| [[CloudTrail.5] CloudTrail trails should be integrated with Amazon CloudWatch Logs](cloudtrail-controls.md#cloudtrail-5) | Not supported – CIS removed this requirement | Not supported – CIS removed this requirement | 3.4 | 2.4 | 
| [[CloudTrail.6] Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible](cloudtrail-controls.md#cloudtrail-6) | Not supported – CIS removed this requirement | Not supported – CIS removed this requirement | 3.3 | 2.3 | 
| [[CloudTrail.7] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket](cloudtrail-controls.md#cloudtrail-7) | 3.4 | 3.4 | 3.6 | 2.6 | 
| [[CloudWatch.1] A log metric filter and alarm should exist for usage of the "root" user](cloudwatch-controls.md#cloudwatch-1) | Not supported – manual check | Not supported – manual check | 4.3 | 3.3 | 
| [[CloudWatch.2] Ensure a log metric filter and alarm exist for unauthorized API calls](cloudwatch-controls.md#cloudwatch-2) | Not supported – manual check | Not supported – manual check | Not supported – manual check | 3.1 | 
| [[CloudWatch.3] Ensure a log metric filter and alarm exist for Management Console sign-in without MFA](cloudwatch-controls.md#cloudwatch-3) | Not supported – manual check | Not supported – manual check | Not supported – manual check | 3.2 | 
| [[CloudWatch.4] Ensure a log metric filter and alarm exist for IAM policy changes](cloudwatch-controls.md#cloudwatch-4) | Not supported – manual check | Not supported – manual check | 4.4 | 3.4 | 
| [[CloudWatch.5] Ensure a log metric filter and alarm exist for CloudTrail configuration changes](cloudwatch-controls.md#cloudwatch-5) | Not supported – manual check | Not supported – manual check | 4.5 | 3.5 | 
| [[CloudWatch.6] Ensure a log metric filter and alarm exist for AWS Management Console authentication failures](cloudwatch-controls.md#cloudwatch-6) | Not supported – manual check | Not supported – manual check | 4.6 | 3.6 | 
| [[CloudWatch.7] Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer managed keys](cloudwatch-controls.md#cloudwatch-7) | Not supported – manual check | Not supported – manual check | 4.7 | 3.7 | 
| [[CloudWatch.8] Ensure a log metric filter and alarm exist for S3 bucket policy changes](cloudwatch-controls.md#cloudwatch-8) | Not supported – manual check | Not supported – manual check | 4.8 | 3.8 | 
| [[CloudWatch.9] Ensure a log metric filter and alarm exist for AWS Config configuration changes](cloudwatch-controls.md#cloudwatch-9) | Not supported – manual check | Not supported – manual check | 4.9 | 3.9 | 
| [[CloudWatch.10] Ensure a log metric filter and alarm exist for security group changes](cloudwatch-controls.md#cloudwatch-10) | Not supported – manual check | Not supported – manual check | 4.10 | 3.10 | 
| [[CloudWatch.11] Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)](cloudwatch-controls.md#cloudwatch-11) | Not supported – manual check | Not supported – manual check | 4.11 | 3.11 | 
| [[CloudWatch.12] Ensure a log metric filter and alarm exist for changes to network gateways](cloudwatch-controls.md#cloudwatch-12) | Not supported – manual check | Not supported – manual check | 4.12 | 3.12 | 
| [[CloudWatch.13] Ensure a log metric filter and alarm exist for route table changes](cloudwatch-controls.md#cloudwatch-13) | Not supported – manual check | Not supported – manual check | 4.13 | 3.13 | 
| [[CloudWatch.14] Ensure a log metric filter and alarm exist for VPC changes](cloudwatch-controls.md#cloudwatch-14) | Not supported – manual check | Not supported – manual check | 4.14 | 3.14 | 
| [[Config.1] AWS Config should be enabled and use the service-linked role for resource recording](config-controls.md#config-1) | 3.3 | 3.3 | 3.5 | 2.5 | 
| [[EC2.2] VPC default security groups should not allow inbound or outbound traffic](ec2-controls.md#ec2-2) | 5.5 | 5.4 | 5.3 | 4.3 | 
| [[EC2.6] VPC flow logging should be enabled in all VPCs](ec2-controls.md#ec2-6) | 3.7 | 3.7 | 3.9 | 2.9 | 
| [[EC2.7] EBS default encryption should be enabled](ec2-controls.md#ec2-7) | 5.1.1 | 2.2.1 | 2.2.1 | Not supported | 
| [[EC2.8] EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)](ec2-controls.md#ec2-8) | 5.7 | 5.6 | Not supported | Not supported | 
| [[EC2.13] Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 22](ec2-controls.md#ec2-13) | Not supported – replaced by requirements 5.3 and 5.4 | Not supported – replaced by requirements 5.2 and 5.3 | Not supported – replaced by requirements 5.2 and 5.3 | 4.1 | 
| [[EC2.14] Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 3389](ec2-controls.md#ec2-14) | Not supported – replaced by requirements 5.3 and 5.4 | Not supported – replaced by requirements 5.2 and 5.3 | Not supported – replaced by requirements 5.2 and 5.3 | 4.2 | 
| [[EC2.21] Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389](ec2-controls.md#ec2-21) | 5.2 | 5.1 | 5.1 | Not supported | 
| [[EC2.53] EC2 security groups should not allow ingress from 0.0.0.0/0 to remote server administration ports](ec2-controls.md#ec2-53) | 5.3 | 5.2 | Not supported | Not supported | 
| [[EC2.54] EC2 security groups should not allow ingress from ::/0 to remote server administration ports](ec2-controls.md#ec2-54) | 5.4 | 5.3 | Not supported | Not supported | 
| [[EFS.1] Elastic File System should be configured to encrypt file data at-rest using AWS KMS](efs-controls.md#efs-1) | 2.3.1 | 2.4.1 | Not supported | Not supported | 
| [[EFS.8] EFS file systems should be encrypted at rest](efs-controls.md#efs-8) | 2.3.1 | Not supported | Not supported | Not supported | 
| [[IAM.1] IAM policies should not allow full "\*" administrative privileges](iam-controls.md#iam-1) | Not supported  | Not supported  | 1.16 | 1.22 | 
| [[IAM.2] IAM users should not have IAM policies attached](iam-controls.md#iam-2) | 1.14 | 1.15 | Not supported | 1.16 | 
| [[IAM.3] IAM users' access keys should be rotated every 90 days or less](iam-controls.md#iam-3) | 1.13 | 1.14 | 1.14 | 1.4 | 
| [[IAM.4] IAM root user access key should not exist](iam-controls.md#iam-4) | 1.3 | 1.4 | 1.4 | 1.12 | 
| [[IAM.5] MFA should be enabled for all IAM users that have a console password](iam-controls.md#iam-5) | 1.9 | 1.10 | 1.10 | 1.2 | 
| [[IAM.6] Hardware MFA should be enabled for the root user](iam-controls.md#iam-6) | 1.5 | 1.6 | 1.6 | 1.14 | 
| [[IAM.8] Unused IAM user credentials should be removed](iam-controls.md#iam-8) | Not supported – see [[IAM.22] IAM user credentials unused for 45 days should be removed](iam-controls.md#iam-22) instead | Not supported – see [[IAM.22] IAM user credentials unused for 45 days should be removed](iam-controls.md#iam-22) instead | Not supported – see [[IAM.22] IAM user credentials unused for 45 days should be removed](iam-controls.md#iam-22) instead | 1.3 | 
| [[IAM.9] MFA should be enabled for the root user](iam-controls.md#iam-9) | 1.4 | 1.5 | 1.5 | 1.13 | 
| [[IAM.11] Ensure IAM password policy requires at least one uppercase letter](iam-controls.md#iam-11) | Not supported – CIS removed this requirement | Not supported – CIS removed this requirement | Not supported – CIS removed this requirement | 1.5 | 
| [[IAM.12] Ensure IAM password policy requires at least one lowercase letter](iam-controls.md#iam-12) | Not supported – CIS removed this requirement | Not supported – CIS removed this requirement | Not supported – CIS removed this requirement | 1.6 | 
| [[IAM.13] Ensure IAM password policy requires at least one symbol](iam-controls.md#iam-13) | Not supported – CIS removed this requirement | Not supported – CIS removed this requirement | Not supported – CIS removed this requirement | 1.7 | 
| [[IAM.14] Ensure IAM password policy requires at least one number](iam-controls.md#iam-14) | Not supported – CIS removed this requirement | Not supported – CIS removed this requirement | Not supported – CIS removed this requirement | 1.8 | 
| [[IAM.15] Ensure IAM password policy requires minimum password length of 14 or greater](iam-controls.md#iam-15) | 1.7 | 1.8 | 1.8 | 1.9 | 
| [[IAM.16] Ensure IAM password policy prevents password reuse](iam-controls.md#iam-16) | 1.8 | 1.9 | 1.9 | 1.10 | 
| [[IAM.17] Ensure IAM password policy expires passwords within 90 days or less](iam-controls.md#iam-17) | Not supported – CIS removed this requirement | Not supported – CIS removed this requirement | Not supported – CIS removed this requirement | 1.11 | 
| [[IAM.18] Ensure a support role has been created to manage incidents with AWS Support](iam-controls.md#iam-18) | 1.16 | 1.17 | 1.17 | 1.2 | 
| [[IAM.20] Avoid the use of the root user](iam-controls.md#iam-20) | Not supported – CIS removed this requirement | Not supported – CIS removed this requirement | Not supported – CIS removed this requirement | 1.1 | 
| [[IAM.22] IAM user credentials unused for 45 days should be removed](iam-controls.md#iam-22) | 1.11 | 1.12 | 1.12 | Not supported – CIS added this requirement in later versions | 
| [[IAM.26] Expired SSL/TLS certificates managed in IAM should be removed](iam-controls.md#iam-26) | 1.18 | 1.19 | Not supported – CIS added this requirement in later versions | Not supported – CIS added this requirement in later versions | 
| [[IAM.27] IAM identities should not have the AWSCloudShellFullAccess policy attached](iam-controls.md#iam-27) | 1.21 | 1.22 | Not supported – CIS added this requirement in later versions | Not supported – CIS added this requirement in later versions | 
| [[IAM.28] IAM Access Analyzer external access analyzer should be enabled](iam-controls.md#iam-28) | 1.19 | 1.20 | Not supported – CIS added this requirement in later versions | Not supported – CIS added this requirement in later versions | 
| [[KMS.4] AWS KMS key rotation should be enabled](kms-controls.md#kms-4) | 3.6 | 3.6 | 3.8 | 2.8 | 
| [[Macie.1] Amazon Macie should be enabled](macie-controls.md#macie-1) | Not supported – manual check | Not supported – manual check | Not supported – manual check | Not supported – manual check | 
| [[RDS.2] RDS DB Instances should prohibit public access, as determined by the PubliclyAccessible configuration](rds-controls.md#rds-2) | 2.2.3 | 2.3.3 | Not supported – CIS added this requirement in later versions | Not supported – CIS added this requirement in later versions | 
| [[RDS.3] RDS DB instances should have encryption at-rest enabled](rds-controls.md#rds-3) | 2.2.1 | 2.3.1 | 2.3.1 | Not supported – CIS added this requirement in later versions | 
| [[RDS.5] RDS DB instances should be configured with multiple Availability Zones](rds-controls.md#rds-5) | 2.2.4 | Not supported – CIS added this requirement in later versions | Not supported – CIS added this requirement in later versions | Not supported – CIS added this requirement in later versions | 
| [[RDS.13] RDS automatic minor version upgrades should be enabled](rds-controls.md#rds-13) | 2.2.2 | 2.3.2 | Not supported – CIS added this requirement in later versions | Not supported – CIS added this requirement in later versions | 
| [[RDS.15] RDS DB clusters should be configured for multiple Availability Zones](rds-controls.md#rds-15) | 2.2.4 | Not supported – CIS added this requirement in later versions | Not supported – CIS added this requirement in later versions | Not supported – CIS added this requirement in later versions | 
| [[S3.1] S3 general purpose buckets should have block public access settings enabled](s3-controls.md#s3-1) | 2.1.4 | 2.1.4 | 2.1.5 | Not supported – CIS added this requirement in later versions | 
| [[S3.5] S3 general purpose buckets should require requests to use TLS](s3-controls.md#s3-5) | 2.1.1 | 2.1.1 | 2.1.2 | Not supported – CIS added this requirement in later versions | 
| [[S3.8] S3 general purpose buckets should block public access](s3-controls.md#s3-8) | 2.1.4 | 2.1.4 | 2.1.5 | Not supported – CIS added this requirement in later versions | 
| [[S3.20] S3 general purpose buckets should have MFA delete enabled](s3-controls.md#s3-20) | 2.1.2 | 2.1.2 | 2.1.3 | Not supported – CIS added this requirement in later versions | 

### ARNs for CIS AWS Foundations Benchmarks
<a name="cisv1.4.0-finding-fields"></a>

When you enable one or more versions of the CIS AWS Foundations Benchmark, you begin receiving findings in the AWS Security Finding Format (ASFF). In ASFF, each version uses the following Amazon Resource Name (ARN):

**CIS AWS Foundations Benchmark v5.0.0**  
`arn:aws:securityhub:{{region}}::standards/cis-aws-foundations-benchmark/v/5.0.0`

**CIS AWS Foundations Benchmark v3.0.0**  
`arn:aws:securityhub:{{region}}::standards/cis-aws-foundations-benchmark/v/3.0.0`

**CIS AWS Foundations Benchmark v1.4.0**  
`arn:aws:securityhub:{{region}}::standards/cis-aws-foundations-benchmark/v/1.4.0`

**CIS AWS Foundations Benchmark v1.2.0**  
`arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0`

You can use the [GetEnabledStandards](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetEnabledStandards.html) operation of the Security Hub CSPM API to find the ARN of an enabled standard.

The preceding values are for `StandardsArn`. However, `StandardsSubscriptionArn` refers to the standard subscription resource that Security Hub CSPM creates when you subscribe to a standard by calling [BatchEnableStandards](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_BatchEnableStandards.html) in a Region.

**Note**  
When you enable a version of the CIS AWS Foundations Benchmark, it can take up to 18 hours for Security Hub CSPM to generate findings for controls that use the same AWS Config service-linked rule as enabled controls in other enabled standards. For more information about the schedule for generating control findings, see [Schedule for running security checks](securityhub-standards-schedule.md).

Finding fields differ if you turn on consolidated control findings. For information about these differences, see [Impact of consolidation on ASFF fields and values](asff-changes-consolidation.md). For sample control findings, see [Samples of control findings](sample-control-findings.md).

### CIS requirements that aren't supported in Security Hub CSPM
<a name="securityhub-standards-cis-checks-not-supported"></a>

As noted in the preceding table, Security Hub CSPM doesn't support every CIS requirement in every version of the CIS AWS Foundations Benchmark. Many of the unsupported requirements can be evaluated only by manually reviewing the state of your AWS resources.