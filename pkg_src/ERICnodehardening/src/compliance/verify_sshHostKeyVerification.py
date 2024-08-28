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
# Name      : verify_sshHostKeyVerification.py
# Purpose   : This script will verify whether ssh host key verification
#             is set to ask or not.
# ********************************************************************
"""

def check_ssh_hostkey_status():
    """ This function will verify ssh host key """
    if 'Verifyhostkeydns ask' in open('/etc/ssh/ssh_config').read() and \
'stricthostkeychecking ask' in open('/etc/ssh/ssh_config').read():
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE \
'enable_sshHostKey_verification.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_ssh_hostkey_status()
