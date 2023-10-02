#!/usr/bin/env bash


if [ -z "$1" -o -z "$2" ]; then
    echo "Usage: $0 AWS_ACCOUNT_NUM AWS_IAM_ROLE"
    exit 1
fi

if ! command -v conjur; then
    echo "ERROR: conjur cli tool is not installed."
    echo "See <https://docs.cyberark.com/conjur-enterprise/13.0/en/Content/Developer/CLI/cli-setup.htm>"
    exit 1
fi    

sed -e 's#{{AWS_ACCOUNT_NUM}}/{{AWS_IAM_ROLE}}#'$1'/'$2'#' toolshed.yml.TPL > toolshed.yml

conjur login
conjur policy load -f authn-iam-toolshed.yml -b conjur/authn-iam
conjur authenticator enable --id authn-iam/toolshed
conjur policy load -f toolshed.yml -b data
conjur policy load -f toolshed-grants.yml -b conjur/authn-iam/toolshed
