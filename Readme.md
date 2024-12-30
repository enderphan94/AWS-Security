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