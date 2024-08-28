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
# Name      : verify_GatewayPorts.py
# Purpose   : This script verifies if GatewayPorts are disabled or not.
# ********************************************************************
"""

def check_gatewayports_status():
    """This script verifies if GatewayPorts are disabled or not"""
    if 'GatewayPorts no' in open('/etc/ssh/ssh_config').read().split('\n'):
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'disable_GatewayPorts.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_gatewayports_status()
