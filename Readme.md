# 1. AWS Security
https://enderphan.notion.site/AWS-1555a7fe2eef80138761ea8cfad3d063

# 2. AWS Penetration Testing
https://enderphan.notion.site/AWS-Pentest-de4443c089b748ef930a0aaf7da9c18e?pvs=4

# Tools

1.	Without OpenAI Analysis

```
./IAM-main.py \
    --profile myProfile \
    --aws-escalate-path awsEscala.py
```

2. With OpenAI Analysis

```
./IAM-main.py \
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