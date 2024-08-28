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
# Name      : verify_icmp_responses.py
# Purpose   : This script verifies ICMP responses are disabled or not
# Reason    : EQEV-93417
# Authour   : XOOHRAN
# Revision  : A
# ********************************************************************
"""
def check_icmp_status():
    """This function verifies if bogus ICMP responses has been disabled or not"""
    if 'net.ipv4.icmp_ignore_bogus_error_responses=1' in open('/etc/sysctl.conf').read():
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'disable_icmp_responses.py' TO MAKE IT COMPLIANT"
if __name__ == '__main__':
    check_icmp_status()
