#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
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
# Name      : verify_login_logout_events.py
# Purpose   : This script verifies login and logout events are collected.
# Reason    : EQEV-124638
# Authour   : ZBARPHU
# Revision  : A
# ********************************************************************
"""

import subprocess
import os

def verify_login_logout():
    """This function verifies login and logout events are collected"""

    if os.path.exists("/etc/audit/rules.d/50-logins.rules") is False:
        return "NON-COMPLIANT: EXECUTE 'ensure_login_logout_events.py' TO MAKE IT COMPLIANT"
    else:
        with open("/etc/audit/rules.d/50-logins.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

    if '-w /var/log/lastlog -p wa -k logins' in data and '-w /var/run/faillock/ -p wa -k logins' \
in data:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'ensure_login_logout_events.py' TO MAKE IT COMPLIANT"
if __name__ == '__main__':
    verify_login_logout()
