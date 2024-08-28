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
# Name      : verify_set_maxauth.py
# Purpose   : This script verifies if the MaxAuthTries parameter is
#             set or not
# Reason    : EQEV-90004
# Author    : xoohran
# Date      : 28-06-2021
#********************************************************************
"""

import subprocess
import os
import logging

def check_maxauthtries():
    """This script verifies if MaxAuthTries parameter is set to 4 or not"""
    if 'MaxAuthTries 4' in open('/etc/ssh/sshd_config').read():
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'set_maxauthtries.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_maxauthtries()
