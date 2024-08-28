#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2022 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : verify_user_group_info.py
# Purpose   : This script verifies the events that modify user/group
#             information are collected.
# Reason    : EQEV-100748
# Authour   : ZBARPHU
# Revision  : A
# ********************************************************************
"""

import subprocess
import os

def check_user_group_info():
    """This function verifies the events that modify user/group information are collected"""

    if os.path.exists("/etc/audit/rules.d/50-identity.rules") is False:
        return "NON-COMPLIANT: EXECUTE 'ensure_user_group_info.py' TO MAKE IT COMPLIANT"
    else:
        with open("/etc/audit/rules.d/50-identity.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

    if '-w /etc/group -p wa -k identity' in data and \
'-w /etc/passwd -p wa -k identity' in data and \
'-w /etc/gshadow -p wa -k identity' in data and \
'-w /etc/shadow -p wa -k identity' in data and \
'-w /etc/security/opasswd -p wa -k identity' in data:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'ensure_user_group_info.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_user_group_info()
