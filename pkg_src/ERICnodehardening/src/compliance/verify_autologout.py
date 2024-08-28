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
# Name      : verify_autologout.py
# Purpose   : This script verifies if automatic logout has been enabled
#             within 0 to 900 or not
# Reason    : EQEV-90962
# Author    : xoohran
# Date      : 15-08-2021
#********************************************************************
"""
import subprocess
def check_autologout():
    """This script verifies if automatic logout has been enabled within 0 to 900 or not"""
    status = subprocess.call("cat /etc/profile | grep -e 'TMOUT=' -e 'readonly \
TMOUT' -e 'export TMOUT' > /dev/null", shell=True)
    if status == 0:
        TMOUT = subprocess.check_output("cat /etc/profile | grep -e 'TMOUT=' | cut -d '=' -f 2", shell=True)
        TMOUT=int(TMOUT)
        if 0 <= TMOUT <= 900:
            return "COMPLIANT"
        else:
            return "NON-COMPLIANT:  EXECUTE 'set_autologout.py' TO MAKE IT COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'set_autologout.py' TO MAKE IT COMPLIANT"
if __name__ == '__main__':
    print check_autologout()