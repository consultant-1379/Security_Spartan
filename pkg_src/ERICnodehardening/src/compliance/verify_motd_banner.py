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
# Name      : verify_motd_banner.py
# Purpose   : This script verifies if an ssh banner message has been
#             set using motd or not.
# ********************************************************************
"""

import os
import filecmp
file_name = "/etc/motd"

def check_motd_banner():
    """This function verifies if an ssh banner message has been set using motd or not"""
    string = ""
    if os.stat(file_name).st_size == 0:
        string = "NON-COMPLIANT: EXECUTE 'set_motd_banner.py' TO MAKE IT COMPLIANT"
    else:
        string = "COMPLIANT"
    return string

if __name__ == '__main__':
    print check_motd_banner()