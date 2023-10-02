# toolshed.yml

# Updated: <2023-10-02 11:53:23 david.hisel>

## Run this command to load the policy
# conjur policy load -f toolshed.yml -b data

- !policy
  id: toolshed
  body:
    # Create a group to hold the hosts
    - !group workloads

    # Host ID must match the AWS ARN (i.e. AccountID/AWS role) of the AWS resource that it represents
    - !host
      id: {{AWS_ACCOUNT_NUM}}/{{AWS_IAM_ROLE}}
      annotations:
        authn/api-key: true

        # Add the host into the group
    - !grant
      role: !group workloads
      member: !host {{AWS_ACCOUNT_NUM}}/{{AWS_IAM_ROLE}}


