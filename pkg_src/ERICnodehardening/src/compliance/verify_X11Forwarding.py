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
# Name      : verify_X11Forwarding.py
# Purpose   : This script will verify whether X11Forwarding is set to
#             no or not.
# ********************************************************************
"""

def x11_forwarding_check():
    """ This function  will verify whether X11Forwarding """
    if 'X11Forwarding no' in open('/etc/ssh/sshd_config').read().split('\n'):
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'disable_X11Forwarding.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    x11_forwarding_check()
