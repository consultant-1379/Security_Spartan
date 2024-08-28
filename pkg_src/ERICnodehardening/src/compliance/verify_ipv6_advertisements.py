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
# Name      : verify_ipv6_advertisements.py
# Purpose   : This script verifies if Ipv6 router advertisements are
              accepted are not
# Reason    : EQEV-93878
# Author    : ZBARPHU
# Revision  : A
# ********************************************************************
"""
def check_ipv6_adv():
    """This function verifies if Ipv6 router advertisements are accepted are not"""
    if 'net.ipv6.conf.all.accept_ra=0' in open('/etc/sysctl.conf').read() and \
'net.ipv6.conf.default.accept_ra=0' in open('/etc/sysctl.conf').read():
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'disable_ipv6_advertisements.py' TO MAKE IT COMPLIANT"
if __name__ == '__main__':
    check_ipv6_adv()
