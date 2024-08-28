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
# Name      : verify_auditconf_immutable.py
# Purpose   : This script verifies that audit configuration is
#             immutable.
# Reason    : EQEV-95305
# Authour   : ZBARPHU
# Revision  : A
# ********************************************************************
"""
import os

def check_auditconf_immutable():
    """This function verifies that audit configuration is immutable"""

    if os.path.exists("/etc/audit/rules.d/99-finalize.rules") is False:
        return "NON-COMPLIANT: EXECUTE 'ensure_auditconf_immutable.py' TO MAKE IT COMPLIANT!"
    else:
        with open("/etc/audit/rules.d/99-finalize.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

    if '-e 2' in data:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'ensure_auditconf_immutable.py' TO MAKE IT COMPLIANT!"

if __name__ == '__main__':
    check_auditconf_immutable()
