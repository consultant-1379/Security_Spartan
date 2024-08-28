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
# Name      : verify_rev_path_filter.py
# Purpose   : This script verifies Reverse Path Filtering is enabled
#             or not
# Reason    : EQEV-93415
# Authour   : ZBARPHU
# Revision  : A
# ********************************************************************
"""
def check_rev_path():
    """This function verifies if Reverse Path Filtering is enabled or not"""
    if 'net.ipv4.conf.all.rp_filter=1' in open('/etc/sysctl.conf').read() and \
'net.ipv4.conf.default.rp_filter=1' in open('/etc/sysctl.conf').read():
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'enable_reverse_path_filter.py' TO MAKE IT COMPLIANT"
if __name__ == '__main__':
    check_rev_path()
