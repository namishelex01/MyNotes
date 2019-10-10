* Lock Away Your AWS Account Root User Access Keys
* Create Individual IAM Users
* Use Groups to Assign Permissions to IAM Users
* Grant Least Privilege
* Get Started Using Permissions with AWS Managed Policies
* Use Customer Managed Policies Instead of Inline Policies
* Use Access Levels to Review IAM Permissions
* Configure a Strong Password Policy for Your Users
* Enable MFA
* Use Roles for Applications That Run on Amazon EC2 Instances
  * A role is an entity that has its own set of permissions, but that isn't a user or group. Roles also don't have their own permanent set of credentials the way IAM users do. 
  * In the case of Amazon EC2, IAM dynamically provides temporary credentials to the EC2 instance, and these credentials are automatically rotated for you.
* Use Roles to Delegate Permissions
  * You can designate which AWS accounts have the IAM users that are allowed to assume the role.
* Do Not Share Access Keys
* Rotate Credentials Regularly
  * $ aws iam create-access-key
  * $ aws iam get-access-key-last-used
  * $ aws iam update-access-key
  * $ aws iam delete-access-key
* Remove Unnecessary Credentials
* Use Policy Conditions for Extra Security - Example
  * Write conditions to specify a range of allowable IP addresses that a request must come from. 
  * Specify that a request is allowed only within a specified date range or time range. You can also set conditions that require the use of SSL or MFA (multi-factor authentication)
* Monitor Activity in Your AWS Account
