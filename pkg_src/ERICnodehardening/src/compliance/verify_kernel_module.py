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
# Name      : verify_kernel_module.py
# Purpose   : This script verifies that the kernel module loading and
#             unloading is collected or not.
# Reason    : EQEV-95304
# Authour   : ZATLPOE
# Revision  : A
# ********************************************************************
"""

import subprocess
import os


def check_kernel_module():
    """This function verifies that kernel module loading and unloading is collected successfully"""

    if os.path.exists("/etc/audit/rules.d/50-modules.rules") is False:
        return "NON-COMPLIANT: EXECUTE 'ensure_kernel_module.py' TO MAKE IT COMPLIANT"
    else:
        with open("/etc/audit/rules.d/50-modules.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        cmd = "getconf LONG_BIT"
        result = subprocess.check_output(cmd, shell=True)
        string = ""
        if int(result) == 64:
            if '-w /sbin/insmod -p x -k modules' in data and '-w /sbin/rmmod -p x -k modules' \
in data and '-w /sbin/modprobe -p x -k modules' in data and '-a always,exit -F arch=b64 -S \
init_module -S delete_module -k modules' in data:
                string = "COMPLIANT"
            else:
                string = "NON-COMPLIANT:  EXECUTE 'ensure_kernel_module.py' TO MAKE IT COMPLIANT"
        elif int(result) == 32:
            if '-w /sbin/insmod -p x -k modules' in data and '-w /sbin/rmmod -p x -k modules' \
in data and '-w /sbin/modprobe -p x -k modules' in data and '-a always,exit -F arch=b32 -S \
init_module -S delete_module -k modules' in data:
                string = "COMPLIANT"
            else:
                string = "NON-COMPLIANT: EXECUTE 'ensure_kernel_module.py' TO MAKE IT COMPLIANT"
        return string

if __name__ == '__main__':
    check_kernel_module()
