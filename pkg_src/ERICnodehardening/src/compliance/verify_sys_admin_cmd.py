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
# Name      : verify_sys_admin_cmd.py
# Purpose   : This script verifies that the system administrator
#             command executions (sudo) are collected.
# Reason    : EQEV-95081
# Authour   : ZBARPHU
# Revision  : A
# ********************************************************************
"""

import subprocess
import os

def check_sys_admin_cmd():
    """This function verifies that successful file system mounts are collected"""

    if os.path.exists("/etc/audit/rules.d/50-actions.rules") is False:
        return "NON-COMPLIANT: EXECUTE 'ensure_sys_admin_cmd.py' TO MAKE IT COMPLIANT"
    else:
        with open("/etc/audit/rules.d/50-actions.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

    cmd = "getconf LONG_BIT"
    result = subprocess.check_output(cmd, shell=True)
    string = ""
    if int(result) == 64:
        if '-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -F auid>=1000 -F \
auid!=4294967295 -S execve -k actions' in data and '-a always,exit -F arch=b32 -C \
euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions' in data:
            string = "COMPLIANT"
        else:
            string = "NON-COMPLIANT:  EXECUTE 'ensure_sys_admin_cmd.py' TO MAKE IT COMPLIANT"
    elif int(result) == 32:
        if '-a exit,always -F arch=b32 -C euid!=uid -F euid=0 -F auid>=1000 -F \
auid!=4294967295 -S execve -k actions' in data:
            string = "COMPLIANT"
        else:
            string = "NON-COMPLIANT: EXECUTE 'ensure_sys_admin_cmd.py' TO MAKE IT COMPLIANT"
    return string

if __name__ == '__main__':
    check_sys_admin_cmd()
