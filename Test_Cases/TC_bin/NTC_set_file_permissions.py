#!/usr/bin/python
"""
# ****************************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ****************************************************************************
#
#
# (c) Ericsson Radio Systems AB 2019 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
#
#
#
# ********************************************************************
# Name       : NTC_set_file_permissions.py
# Purpose    : Test Negative Scenarios of File permissions.
#
# ********************************************************************
"""
import subprocess
import os
import logging
import time
import commands as c

from TC_set_file_permissions import check_permissions

def check_weak_permissions():
    """This script checks the negative scenario for file permissions """

    os.system("chmod 644 /etc/at.allow")
    status = check_permissions()
    os.system("/ericsson/security/bin/set_file_permissions.py > /dev/null 2>&1")
    if status == "FAIL":
        return "SUCCESS"
    else:
        return "FAIL"


if __name__ == '__main__':

    print check_weak_permissions()
