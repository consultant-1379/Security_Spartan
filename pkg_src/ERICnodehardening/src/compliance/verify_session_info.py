#!/usr/bin/python
"""
# *********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# *********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2023 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : verify_session_info.py
# Purpose   : This script ensures session initiation information
#             are collected.
# Reason    : EQEV-124639
# Authour   : ZBARPHU
# Revision  : A
# ********************************************************************
"""

import subprocess
import os

def verify_audit_session_info():
    """This function verifies that session initiation information are collected"""

    if os.path.exists("/etc/audit/rules.d/50-session.rules") is False:
        return "NON-COMPLIANT: EXECUTE 'ensure_session_info.py' TO MAKE IT COMPLIANT"
    else:
        with open("/etc/audit/rules.d/50-session.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

    if '-w /var/run/utmp -p wa -k session' in data and '-w /var/log/wtmp -p wa -k logins' in data \
and '-w /var/log/btmp -p wa -k logins' in data:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'ensure_session_info.py' TO MAKE IT COMPLIANT"
if __name__ == '__main__':
    verify_audit_session_info()
