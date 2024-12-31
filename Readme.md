# 1. AWS Security
https://enderphan.notion.site/AWS-1555a7fe2eef80138761ea8cfad3d063

# 2. AWS Penetration Testing
https://enderphan.notion.site/AWS-Pentest-de4443c089b748ef930a0aaf7da9c18e?pvs=4

# 3. Usage Script

The tool takes the profile configured in the AWS, you need to first configure the profile.

```aws configure --profile myProfile```

1. Without OpenAI Analysis

```./IAM-main.py \
    --profile myProfile \
    --aws-escalate-path awsEscala.py
```

2. With OpenAI Analysis

```./IAM-main.py \
    --profile myProfile \
    --aws-escalate-path awsEscala.py \
    --openai-api-key <YOUR_API_KEY_HERE>
```

## Sample output

```
python3.10 IAM-main.py  --profile cha1 --aws-escalate-path awsEscala.py --openai-api-key $OPEN_AI

Enumerating for user: iam-secrets-unleashed-privesc-1735487289906-Adam
Error listing managed policies for iam-secrets-unleashed-privesc-1735487289906-Adam: An error occurred (AccessDenied) when calling the ListAttachedUserPolicies operation: User: arn:aws:iam::921234892411:user/iam-secrets-unleashed-privesc-1735487289906-Adam is not authorized to perform: iam:ListAttachedUserPolicies on resource: user iam-secrets-unleashed-privesc-1735487289906-Adam because no permissions boundary allows the iam:ListAttachedUserPolicies action
Error listing roles: An error occurred (AccessDenied) when calling the ListRoles operation: User: arn:aws:iam::921234892411:user/iam-secrets-unleashed-privesc-1735487289906-Adam is not authorized to perform: iam:ListRoles on resource: arn:aws:iam::921234892411:role/ because no identity-based policy allows the iam:ListRoles action
Error listing roles: An error occurred (AccessDenied) when calling the ListRoles operation: User: arn:aws:iam::921234892411:user/iam-secrets-unleashed-privesc-1735487289906-Adam is not authorized to perform: iam:ListRoles on resource: arn:aws:iam::921234892411:role/ because no identity-based policy allows the iam:ListRoles action

No roles detected that the user can assume.

--- Summary of Relationships and Enumeration Commands ---

User: iam-secrets-unleashed-privesc-1735487289906-Adam

Groups the user belongs to:
- iam-secrets-unleashed-privesc-1735487289906-Developers

No policies attached to the user.

Group Policies:
- Group: iam-secrets-unleashed-privesc-1735487289906-Developers
  Managed Policies:
    - iam-secrets-unleashed-privesc-1735487289906-developers (ARN: arn:aws:iam::921234892411:policy/iam-secrets-unleashed-privesc-1735487289906-developers)

No roles the user can assume.

No role policies found.

=== Running aws_escalate.py with extracted credentials ===

[aws_escalate.py stdout]:
Collecting policies for 1 users...
List attached user policies failed: An error occurred (AccessDenied) when calling the ListAttachedUserPolicies operation: User: arn:aws:iam::921234892411:user/iam-secrets-unleashed-privesc-1735487289906-Adam is not authorized to perform: iam:ListAttachedUserPolicies on resource: user iam-secrets-unleashed-privesc-1735487289906-Adam because no permissions boundary allows the iam:ListAttachedUserPolicies action
  iam-secrets-unleashed-privesc-1735487289906-Adam... done!
  Done.

User: iam-secrets-unleashed-privesc-1735487289906-Adam
  POTENTIAL: AttachRolePolicy

  POTENTIAL: AddUserToGroup

Privilege escalation check completed. Results stored to ./all_user_privesc_scan_results_1735487478.458605.csv


[+] Finished: Enumeration and aws_escalate checks.



=== SENDING OUTPUT TO OPENAI FOR ANALYSIS ===


=== OPENAI ANALYSIS RESULT ===

The output indicates potential vulnerabilities related to privilege escalation for the user `iam-secrets-unleashed-privesc-1735487289906-Adam`. Here are the identified vulnerabilities:

1. **AttachRolePolicy Potential**: The user has the potential to attach policies to roles. If the user can attach a policy that grants higher privileges or administrative access to a role they can assume, this could lead to privilege escalation.

2. **AddUserToGroup Potential**: The user has the potential to add themselves or other users to groups. If the user can add themselves to a group with higher privileges, they could escalate their permissions.

These potential vulnerabilities could be exploited by the user to gain higher privileges within the AWS environment, potentially allowing unauthorized access to resources or sensitive operations.
```

You can find other tools here: https://enderphan.notion.site/IAM-Escalation-1695a7fe2eef80d0a0b1e89fcb1b2233?pvs=97#1695a7fe2eef80d3a8ddd49dab3250e7

# 4. Other Tools

# Tools

## **IAMActionHunter**

https://github.com/RhinoSecurityLabs/IAMActionHunter

Quickly and easily evaluate one or more IAM policies to find issues.

This is a tool you can use to more quickly understand what the vulnerability might be across one policy or across multiple policies.

## **IAMFinder**

https://github.com/prisma-cloud/IAMFinder

IAMFinder enumerates and finds users and IAM roles in a target AWS account.

## **EnumerateIAM**

https://github.com/andresriancho/enumerate-iam

Enumerate the permissions associated with an AWS credential set. This tool tries to brute force all API calls allowed by the IAM policy. The calls performed by this tool are all non-destructive (only get* and list* calls are performed). Great for finding weaknesses you may not have manually found.

## **PMapper**

https://github.com/nccgroup/PMapper

A tool for quickly evaluating IAM permissions in AWS.

## **aws_escalate.py**

https://github.com/RhinoSecurityLabs/Security-Research/blob/master/tools/aws-pentest-tools/aws_escalate.py

A script that can help you find privesc paths.

## **Pacu**

https://github.com/RhinoSecurityLabs/pacu

# 5. Enumeration commands

First, we need to know our identity

```aws sts get-caller-identity --profile <xxx>```

And then we need to gather all information about the groups, policies and roles which are relevant to the current account:

```
aws iam list-groups

aws iam list-groups-for-user --user-name <xxx>

aws iam list-attached-user-policies --user-name <xxx>

aws iam list-user-policies --user-name <xxx>

aws iam list-attached-group-policies --group-name <xxx>

aws iam list-group-policies --group-name <xxx>

```

And then roles:

```

aws iam list-roles # Get roles in the AWS account

aws iam get-role --role-name <role-name>

aws iam list-role-policies --role-name <name>

aws iam get-role-policy --role-name <name> --policy-name <name> 

aws iam list-attached-role-policies --role-name <role-name> 

```

List policy verions:

```
aws iam list-attached-group-policies --group-name <groupname>

aws iam get-policy --policy-arn <policy_arn>

aws iam list-policy-versions --policy-arn <arn>

aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/example-policy --version-id <v1 or v2 or ...>

aws iam set-default-policy-version --policy-arn <policy-arn> --version-id <new-version-id> --profile <XXX>
```