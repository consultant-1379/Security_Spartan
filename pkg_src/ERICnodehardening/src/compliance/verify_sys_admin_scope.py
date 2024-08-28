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
# Name      : verify_sys_admin_scope.py
# Purpose   : This script verifies the changes to system administration
#             scope (sudoers) is collected.
# Reason    : EQEV-100747
# Authour   : ZBARPHU
# Revision  : A
# ********************************************************************
"""

import subprocess
import os

def check_sys_admin_scope():
    """This function verifies the events that modify user/group information are collected"""

    if os.path.exists("/etc/audit/rules.d/50-scope.rules") is False:
        return "NON-COMPLIANT: EXECUTE 'ensure_sys_admin_scope.py' TO MAKE IT COMPLIANT"
    else:
        with open("/etc/audit/rules.d/50-scope.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

    if '-w /etc/sudoers -p wa -k scope' in data and \
'-w /etc/sudoers.d/ -p wa -k scope' in data:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'ensure_sys_admin_scope.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_sys_admin_scope()
