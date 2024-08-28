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
# Name      : verify_ssh_emptypasswords.py
# Purpose   : This script verifies if SSH permit empty passwords is
#             disabled or not.
# Reason    : EQEV-96571
# Author    : ZBARPHU
# Revision  : A
# ********************************************************************
"""
def check_ssh_emptypasswords():
    """This function verifies if SSH permit empty passwords is disabled or not"""

    if 'PermitEmptyPasswords no' in open('/etc/ssh/sshd_config').read():
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'disable_ssh_emptypasswords.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_ssh_emptypasswords()
