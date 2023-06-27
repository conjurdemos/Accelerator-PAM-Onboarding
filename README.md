# Accelerator PAS Automation
==========================

## MVP Goals:
- Demonstrate best-practices for end-to-end workflows around PrivCloud & Conjur Cloud
- Leverage Flows for automation
- Leverage Conjur Cloud to eliminate secret zero

### Proposed workflow:
- Bootstrap host is an EC2 instance running:
  - request UI form
  - automation to create EC2 instances
  - authn logic to PCloud & Conjur Cloud
- User authenticates and enters data for EC2 compute request in UI
- Bootstrap host has AWS role for EC2 admin
- Bootstrap logic creates new EC2 instance, captures SSH-key
- Bootstrap logic uses IAM role & Conjur authn-iam to retrieve PCloud admin password
- Bootstrap logic uses admin password to authn to PCloud
- Calls Flows webhook w/ Conjur & PCloud short-lived tokens
- Reuse End2End-Provisioning flow to onboard SSH-key account & Conjur workload:
  - create Safe
  - create SSH-key account for new EC2 instance
  - add Conjur Sync user to safe
  - create Conjur workload (authn-apikey)
  - grant Safe consumers role to Conjur workload
  - notify user of workload name & apikey
- Second lamda authenticates to Conjur, retrieves SSH-key, accesses EC2 instance
