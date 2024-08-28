#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2021 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : verify_system_access.py
# Purpose   : This script verifies that the system access are
#             collected or not.
# Reason    : EQEV-94614
# Authour   : ZATLPOE
# Revision  : A
# ********************************************************************
"""

import os


def check_system_access():
    """This function verifies that the system access are collected successfully"""

    if os.path.exists("/etc/audit/rules.d/50-MAC_policy.rules") is False:
        return "NON-COMPLIANT: EXECUTE 'ensure_system_access.py' TO MAKE IT COMPLIANT"
    else:
        with open("/etc/audit/rules.d/50-MAC_policy.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        if '-w /etc/selinux/ -p wa -k MAC-policy' in data and \
'-w /usr/share/selinux/ -p wa -k MAC-policy' in data:
            return "COMPLIANT"
        else:
            return "NON-COMPLIANT:  EXECUTE 'ensure_system_access.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_system_access()
