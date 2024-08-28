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
# Name      : verify_ssh_timeout.py
# Purpose   : This script verifies if SSH idle timeout is set or not
# Reason    : EQEV-92524
# Author    : zdodpra
# Date      : 28-09-2021
#********************************************************************
"""
def check_sshtimeout():
    """This script verifies if ClientAliveInterval and ClientAliveCount \
is set according to recommendation or not"""
    fin = open('/etc/ssh/sshd_config', 'r')
    filecontent = fin.read()
    fin.close()
    if ("ClientAliveInterval 900\n" or "ClientAliveCountMax 0\n") in filecontent:
        return "COMPLIANT"
    elif "ClientAliveInterval" in filecontent or "ClientAliveCountMax" in filecontent:
        return "NON-COMPLIANT:  EXECUTE 'enforce_ssh_timeout.py' TO MAKE IT COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'enforce_ssh_timeout.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_sshtimeout()
