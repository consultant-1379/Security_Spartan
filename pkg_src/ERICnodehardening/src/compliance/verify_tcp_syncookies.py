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
# *********************************************************************
# Name      : verify_tcp_syncookies.py
# Purpose   : This script verifies if tcp syn cookies has been enabled or not.
# Author    : ZATLPOE
# Reason    : EQEV-93877
# Revision  : A
# *********************************************************************
"""
def check_tcp_syncookies():
    """This function verifies if tcp syn cookies has been enabled or not"""
    if 'net.ipv4.tcp_syncookies=1' in open('/etc/sysctl.conf').read():
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'enable_tcp_syncookies.py' TO MAKE IT COMPLIANT"
if __name__ == '__main__':
    check_tcp_syncookies()
