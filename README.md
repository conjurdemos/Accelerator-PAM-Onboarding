# Accelerator PAS Automation
==========================

## MVP Goals:
- Demonstrate best-practices for end-to-end workflows around PrivCloud & Conjur Cloud
- Leverage Flows for automation
- Leverage Conjur Cloud to eliminate secret zero

### Proposed workflow:
![PAS Automation MVPv1](https://github.com/conjurdemos/Accelerator-PAS-Automation/blob/main/PASAutomation-MVPv1.png?raw=true)

- Bootstrap host is an EC2 instance running:
  - request UI form
  - automation to create EC2 instances
  - authn logic to PCloud & Conjur Cloud
- User authenticates and enters data for EC2 compute request in UI
- Bootstrap host has local credfile for EC2 admin creds
- Bootstrap logic creates new Windows EC2 instance, captures admin password
- Bootstrap logic uses IAM role & Conjur authn-iam to retrieve PCloud admin password
- Bootstrap logic uses admin password to authn to PCloud
- Calls Flows webhook w/ Conjur & PCloud short-lived tokens
- Makes REST calls to onboard Windows account in existing safe:
  - create Windows password account for new EC2 instance
  - notify user
- User accesses EC2 instance via DPA or somesuch...
