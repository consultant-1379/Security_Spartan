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
# Name      : verify_user_priviliged_cmd.py
# Purpose   : This script verifies that ensures the use of privileged
            : commands is collected.
# Reason    : EQEV-95303
# Authour   : ZBARPHU
# Revision  : A
# ********************************************************************
"""

import subprocess
import os

def check_user_privileged_cmd():
    """This script verifies that ensures the use of privileged commands is collected"""

    if os.path.exists("/etc/audit/rules.d/50-privileged.rules") is False:
        return "NON-COMPLIANT: EXECUTE 'ensure_user_priviliged_cmd.py' TO MAKE IT COMPLIANT"
    else:
        with open("/etc/audit/rules.d/50-privileged.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

    if os.path.getsize('/etc/audit/rules.d/50-privileged.rules') == 0:
        return "NON-COMPLIANT:  EXECUTE 'ensure_user_priviliged_cmd.py' TO MAKE IT COMPLIANT"
    else:
        return "COMPLIANT"

if __name__ == '__main__':
    check_user_privileged_cmd()
