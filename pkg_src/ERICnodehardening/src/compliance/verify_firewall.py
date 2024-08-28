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
# Name      : verify_firewall.py
# Purpose   : This script verifies if the firewalld service is in
#             active and enabled state or not.
# ********************************************************************
"""

import subprocess
return_statement = "NON-COMPLIANT:  EXECUTE 'enable_firewall.py' TO MAKE IT COMPLIANT"

def check_firewall():
    """This script verifies if the firewalld service is in active and enabled state or not"""

    active_status = subprocess.check_output("systemctl status firewalld | grep -i Active | \
cut -d':' -f 2 | cut -d ' ' -f 2", shell=True)
    enabled_status = subprocess.check_output("systemctl status firewalld | sed -n '/Loaded:/p' | \
cut -d ';' -f 2 | cut -d ' ' -f 2", shell=True)

    string = ""
    if active_status == "inactive\n" and enabled_status == "disabled\n":
        string = return_statement
    elif active_status == "inactive\n" and enabled_status == "enabled\n":
        string = return_statement
    elif active_status == "active\n" and enabled_status == "disabled\n":
        string = return_statement
    else:
        string = "COMPLIANT"
    return string

if __name__ == '__main__':
    check_firewall()
