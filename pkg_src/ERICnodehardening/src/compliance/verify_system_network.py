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
# Name      : verify_system_network.py
# Purpose   : This script ensures that the system network environment
#             are collected or not.
# Reason    : EQEV-94613
# Authour   : ZATLPOE
# Revision  : A
# ********************************************************************
"""

import subprocess
import os


def check_system_network():
    """This function verifies that the system network environment are collected successfully"""

    cmd = "getconf LONG_BIT"
    result = subprocess.check_output(cmd, shell=True)

    if os.path.exists("/etc/audit/rules.d/50-system_local.rules") is False:
        return "NON-COMPLIANT: EXECUTE 'ensure_system_network.py' TO MAKE IT COMPLIANT"
    else:
        with open("/etc/audit/rules.d/50-system_local.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')
        string = ""
        if int(result) == 64:
            if '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale' in \
data and '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale' in data \
and '-w /etc/issue -p wa -k system-locale' in data and '-w /etc/issue.net -p wa -k system-locale' \
in data and '-w /etc/hosts -p wa -k system-locale' in data and \
'-w /etc/sysconfig/network -p wa -k system-locale' in data:
                string = "COMPLIANT"
            else:
                string = "NON-COMPLIANT:  EXECUTE 'ensure_system_network.py' TO MAKE IT COMPLIANT"
        elif int(result) == 32:
            if '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale' in \
data and '-w /etc/issue -p wa -k system-locale' in data and \
'-w /etc/issue.net -p wa -k system-locale' in data and '-w /etc/hosts -p wa -k system-locale' in \
data and '-w /etc/sysconfig/network -p wa -k system-locale' in data:
                string = "COMPLIANT"
            else:
                string = "NON-COMPLIANT: EXECUTE 'ensure_system_network.py' TO MAKE IT COMPLIANT"
        return string
if __name__ == '__main__':
    check_system_network()
