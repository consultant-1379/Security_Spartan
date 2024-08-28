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
# Name      : verify_suspicious_packets.py
# Purpose   : This script verifies suspicious packets is enabled or not
# Reason    : EQEV-93413
# Authour   : ZBARPHU
# Revision  : A
# ********************************************************************
"""
def check_packets():
    """This function verifies if suspicious packets is enabled or not"""
    if 'net.ipv4.conf.all.log_martians=1' in open('/etc/sysctl.conf').read() and \
'net.ipv4.conf.default.log_martians=1' in open('/etc/sysctl.conf').read():
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'enable_suspicious_packets.py' TO MAKE IT COMPLIANT"
if __name__ == '__main__':
    check_packets()
