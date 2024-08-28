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
# *********************************************************************
# Name      : verify_disable_root_switch.py
# Purpose   : This script verifies root user switch is being restricted.
# Reason    : EQEV-111732
# Authour   : ZBARPHU
# Revision  : A
# *********************************************************************
"""
import subprocess

def verify_disable_root_switch():
    """This function verifies root user switch is being restricted"""
    return_string = "NON-COMPLIANT:  EXECUTE 'disable_root_switch.py' TO MAKE IT COMPLIANT"

    try:
        sudo = ["#%PAM-1.0", "auth       required        sudo", "account    sufficient      sudo", \
"password   include         sudo", "session    optional        pam_keyinit.so force revoke", \
"session    include         sudo"]
        data = subprocess.check_output("cat /etc/pam.d/sudo-i", \
shell=True, stderr=subprocess.STDOUT).strip()
        if all(word in data for word in sudo):
            return "COMPLIANT"
        else:
            return return_string
    except subprocess.CalledProcessError:
        return return_string

if __name__ == '__main__':
    verify_disable_root_switch()