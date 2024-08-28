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
# Name      : verify_disec_access.py
# Purpose   : This script verifies discretionary access control permission
#             modification events are collected
# Reason    : EQEV-94615
# Authour   : ZBARPHU
# Revision  : A
# ********************************************************************
"""

import subprocess
import os

def check_disec_access():
    """This function verifies discretionary access control permission modification \
events are collected"""

    if os.path.exists("/etc/audit/rules.d/50-perm_mod.rules") is False:
        return "NON-COMPLIANT: EXECUTE 'discretionary_access_control.py' TO MAKE IT COMPLIANT"
    else:
        with open("/etc/audit/rules.d/50-perm_mod.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

    cmd = "getconf LONG_BIT"
    result = subprocess.check_output(cmd, shell=True)
    string = ""
    if int(result) == 64:
        if '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F \
auid!=4294967295 -k perm_mod' and '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F \
auid>=1000 -F auid!=4294967295 -k perm_mod' and '-a always,exit -F arch=b64 -S chown -S fchown -S \
fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod' and '-a always,exit -F \
arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod' \
and '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S \
lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' \
and '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S \
lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' in data:
            string = "COMPLIANT"
        else:
            string = "NON-COMPLIANT:  EXECUTE 'discretionary_access_control.py' TO MAKE IT COMPLIANT"
    elif int(result) == 32:
        if '--a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F \
auid!=4294967295 -k perm_mod' in data and '-a always,exit -F arch=b32 -S chown -S fchown -S \
fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod' and '-a always,exit -F \
arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S \
fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' in data:
            string = "COMPLIANT"
        else:
            string = "NON-COMPLIANT: EXECUTE 'discretionary_access_control.py' TO MAKE IT COMPLIANT"
    return string

if __name__ == '__main__':
    check_disec_access()
