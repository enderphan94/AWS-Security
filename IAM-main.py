#!/usr/bin/env python3
import argparse
import subprocess
import sys
import boto3
import openai
import io
import contextlib
from botocore.exceptions import ClientError

################################################################################
#                       PART 1: Your Original Enumeration Code                 #
################################################################################

def get_account_id(session):
    """Retrieve the AWS account ID using the STS API."""
    sts_client = session.client('sts')
    try:
        response = sts_client.get_caller_identity()
        return response['Account'], response['Arn']
    except ClientError as e:
        print(f"Error getting account ID: {e}")
        return None, None

def list_user_groups(iam_client, username):
    """List all groups that a user belongs to."""
    try:
        response = iam_client.list_groups_for_user(UserName=username)
        return response['Groups']
    except ClientError as e:
        print(f"Error listing groups for user {username}: {e}")
        return []

def list_group_policies(iam_client, group_name):
    """List all inline and managed policies of a group."""
    try:
        inline_policies = iam_client.list_group_policies(GroupName=group_name)['PolicyNames']
        managed_policies = iam_client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
        return inline_policies, managed_policies
    except ClientError as e:
        print(f"Error listing policies for group {group_name}: {e}")
        return [], []

def list_user_policies(iam_client, username):
    """List all inline policies attached to a user."""
    try:
        response = iam_client.list_user_policies(UserName=username)
        return response['PolicyNames']
    except ClientError as e:
        print(f"Error listing user policies for {username}: {e}")
        return []

def list_user_managed_policies(iam_client, username):
    """List managed policies attached to a user."""
    try:
        response = iam_client.list_attached_user_policies(UserName=username)
        return response['AttachedPolicies']
    except ClientError as e:
        print(f"Error listing managed policies for {username}: {e}")
        return []

def list_roles(iam_client):
    """List all roles."""
    try:
        response = iam_client.list_roles()
        return response['Roles']
    except ClientError as e:
        print(f"Error listing roles: {e}")
        return []

def list_role_policies(iam_client, role_name):
    """List all inline and managed policies of a role."""
    try:
        inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
        managed_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
        return inline_policies, managed_policies
    except ClientError as e:
        print(f"Error listing policies for role {role_name}: {e}")
        return [], []

def summarize_relationships(user_name, groups, roles, user_policies, group_policies, role_policies):
    """Summarize the relationships and enumeration."""
    print("\n--- Summary of Relationships and Enumeration Commands ---\n")

    print(f"User: {user_name}")
    if groups:
        print("\nGroups the user belongs to:")
        for group in groups:
            print(f"- {group['GroupName']}")
    else:
        print("\nNo groups the user belongs to.")

    if user_policies['inline'] or user_policies['managed']:
        print("\nUser's Policies:")
        if user_policies['inline']:
            print(f"  Inline Policies: {', '.join(user_policies['inline'])}")
        if user_policies['managed']:
            print("  Managed Policies:")
            for policy in user_policies['managed']:
                print(f"  - {policy['PolicyName']} (ARN: {policy['PolicyArn']})")
    else:
        print("\nNo policies attached to the user.")

    if group_policies:
        print("\nGroup Policies:")
        for grp, pols in group_policies.items():
            print(f"- Group: {grp}")
            if pols['inline']:
                print(f"  Inline Policies: {', '.join(pols['inline'])}")
            if pols['managed']:
                print("  Managed Policies:")
                for policy in pols['managed']:
                    print(f"    - {policy['PolicyName']} (ARN: {policy['PolicyArn']})")
    else:
        print("\nNo group policies found.")

    if roles:
        print("\nRoles the user can assume:")
        for r in roles:
            print(f"- {r['RoleName']}")
    else:
        print("\nNo roles the user can assume.")

    if role_policies:
        print("\nRole Policies:")
        for role, pols in role_policies.items():
            print(f"- Role: {role}")
            if pols['inline']:
                print(f"  Inline Policies: {', '.join(pols['inline'])}")
            if pols['managed']:
                print("  Managed Policies:")
                for policy in pols['managed']:
                    print(f"    - {policy['PolicyName']} (ARN: {policy['PolicyArn']})")
    else:
        print("\nNo role policies found.")

def check_assume_role_vulnerability(iam_client, username):
    """Check if the user has permissions to assume any role and print a warning."""
    try:
        roles = list_roles(iam_client)
        vulnerable_roles = []

        for role in roles:
            assume_role_policy = role.get('AssumeRolePolicyDocument', {})
            statements = assume_role_policy.get('Statement', [])

            for statement in statements:
                if statement.get('Effect') == 'Allow' and 'sts:AssumeRole' in statement.get('Action', []):
                    condition = statement.get('Condition', {})
                    arn_equals = condition.get('ArnEquals', {}).get('aws:PrincipalArn', "")
                    # If the condition specifically ends with our username, we have a match
                    if arn_equals.endswith(username):
                        vulnerable_roles.append(role['RoleName'])

        if vulnerable_roles:
            print("\nWARNING: The following roles can be assumed by the user:")
            for r in vulnerable_roles:
                print(f"- {r}")
        else:
            print("\nNo roles detected that the user can assume.")

    except ClientError as e:
        print(f"Error checking for assume role vulnerabilities: {e}")

def enumerate_user(iam_client, session, user_name):
    """Enumerate a user, their groups, roles, and all related policies."""
    print(f"\nEnumerating for user: {user_name}")

    # Groups and their policies
    groups = list_user_groups(iam_client, user_name)
    group_policies = {}
    for grp in groups:
        in_pols, man_pols = list_group_policies(iam_client, grp['GroupName'])
        group_policies[grp['GroupName']] = {
            'inline': in_pols,
            'managed': man_pols
        }

    # User policies
    inline_policies = list_user_policies(iam_client, user_name)
    managed_policies = list_user_managed_policies(iam_client, user_name)
    user_policies = {'inline': inline_policies, 'managed': managed_policies}

    # Roles and their policies
    roles = list_roles(iam_client)
    role_policies = {}
    for r in roles:
        in_pols, man_pols = list_role_policies(iam_client, r['RoleName'])
        role_policies[r['RoleName']] = {'inline': in_pols, 'managed': man_pols}

    # Check assume role vulnerability
    check_assume_role_vulnerability(iam_client, user_name)

    # Summarize
    summarize_relationships(user_name, groups, roles, user_policies, group_policies, role_policies)

################################################################################
#                   PART 2: RUN aws_escalate.py WITH CREDENTIALS               #
################################################################################

def run_aws_escalate(aws_escalate_path, session):
    """
    Extract credentials from the session (via --profile) and pass them
    to aws_escalate.py via --access-key-id and --secret-key arguments.
    """
    creds = session.get_credentials()
    if not creds:
        print("[!] Unable to retrieve credentials from the session.")
        return

    frozen_creds = creds.get_frozen_credentials()
    access_key = frozen_creds.access_key
    secret_key = frozen_creds.secret_key

    print("\n=== Running aws_escalate.py with extracted credentials ===")
    cmd = [
        sys.executable,
        aws_escalate_path,
        "--access-key-id", access_key,
        "--secret-key", secret_key
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        print("\n[aws_escalate.py stdout]:")
        if proc.stdout:
            print(proc.stdout)
        if proc.stderr:
            print("\n[aws_escalate.py stderr]:")
            print(proc.stderr)
    except FileNotFoundError:
        print(f"[!] Could not find aws_escalate.py at: {aws_escalate_path}")
    except Exception as e:
        print(f"[!] Error running aws_escalate.py: {e}")

################################################################################
#                          PART 3: OPENAI EVALUATION                           #
################################################################################

def analyze_with_openai(api_key, content):
    """
    Sends the combined output (enumeration + aws_escalate) to OpenAI 
    and asks for possible vulnerabilities and exploitation methods.
    """
    import openai
    openai.api_key = api_key

    system_message = (
        "You are a cybersecurity assistant. The user is providing "
        "AWS IAM enumeration and escalation tool output. Summarize "
        "any potential vulnerabilities and how they can be exploited."
    )
    user_message = (
        f"Here is the output:\n\n{content}\n\n"
        "Please identify any potential vulnerabilities and do not give out recommendations"
    )

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_message},
            ],
            temperature=0.3,
        )
        return response['choices'][0]['message']['content']
    except openai.error.OpenAIError as e:
        return f"[!] OpenAI Error: {e}"
    except Exception as e:
        return f"[!] Unexpected error calling OpenAI: {e}"

################################################################################
#                               MAIN LOGIC                                     #
################################################################################

def parse_args():
    parser = argparse.ArgumentParser(
        description="Combine IAM enumeration with Rhino’s aws_escalate.py, and optionally evaluate via OpenAI."
    )
    parser.add_argument('--profile', required=True, help='AWS CLI profile name to use.')
    parser.add_argument('--aws-escalate-path', required=True, 
                        help='Path to aws_escalate.py script from Rhino Security Labs.')
    parser.add_argument('--openai-api-key', required=False,
                        help='OpenAI API key for evaluation. If omitted, no AI analysis is done.')
    return parser.parse_args()

def main():
    args = parse_args()

    # 1) Create a Boto3 Session from --profile
    session = boto3.Session(profile_name=args.profile)
    iam_client = session.client('iam')

    # 2) Identify user from STS
    account_id, caller_arn = get_account_id(session)
    if not caller_arn:
        print("Error: Unable to retrieve user information.")
        sys.exit(1)

    username = caller_arn.split('/')[-1]

    # We'll capture all printed output (enumeration + escalation) in one string
    # so we can optionally send it to OpenAI afterward.
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        # 3) Do your enumeration
        enumerate_user(iam_client, session, username)

        # 4) Run aws_escalate.py with the same credentials
        run_aws_escalate(args.aws_escalate_path, session)

        print("\n[+] Finished: Enumeration and aws_escalate checks.\n")

    # This is the combined output from everything above.
    combined_output = buf.getvalue()

    # Print it to the real stdout so the user sees it too
    print(combined_output)

    # 5) If an OpenAI API key is provided, do the AI analysis
    if args.openai_api_key:
        print("\n=== SENDING OUTPUT TO OPENAI FOR ANALYSIS ===\n")
        ai_analysis = analyze_with_openai(args.openai_api_key, combined_output)
        print("\n=== OPENAI ANALYSIS RESULT ===\n")
        print(ai_analysis)
    else:
        print("[Info] No --openai-api-key provided, skipping AI analysis.")

if __name__ == "__main__":
    main()