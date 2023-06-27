# Accelerator PAS Automation
==========================

##MVP Goals:
- Demonstrate best-practices for workflows around PrivCloud & Conjur Cloud
- Leverage Flows for automation
- Leverage Conjur Cloud to eliminate secret zero

###Proposed workflow:
- Onboarding Lambda has AWS role for EC2 admin
- Creates new EC2 instance w/ SSH-key
- Uses IAM role & Conjur authn-iam to retrieve PCloud admin password
- Uses password to authn to PCloud
- Calls Flows w/ Conjur & PCloud short-lived tokens
- Reuse End2End-Provisioning flow to onboard SSH-key account & Conjur workload:
  - create Safe
  - create SSH-key account for new EC2 instance
  - add Conjur Sync user to safe
  - create Conjur workload (authn-apikey)
  - grant Safe consumers role to Conjur workload
  - notify user of workload name & apikey
- Second lamda authenticates to Conjur, retrieves SSH-key, accesses EC2 instance
