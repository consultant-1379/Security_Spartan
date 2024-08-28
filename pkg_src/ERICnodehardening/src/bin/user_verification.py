#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2023 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name     : user_verification.py
# Purpose  : This script verifies the user and the user privileges for
#            executing NH scripts.
# Author   : ZBARPHU
# Revision : A
# Reason   : EQEV-106687
# ********************************************************************
"""

import os
import subprocess
import getpass

def user_verification():
    """This function verifies the user who is executing the script is present in \
ENIQ_ADMIN_ROLE group."""

try:
    if os.environ.has_key('SUDO_USER'):
        username = os.environ['SUDO_USER']
        user_group = subprocess.check_output("lid -g -n ENIQ_ADMIN_ROLE", shell=True).split()
        if username in user_group:
            print"\nThe script is executed by " +username+ " and the user is present in \
Privileged user group!"

        elif username == "root":
            print "\nThe script is being executed as root user!"

        else:
            username not in user_group
            print "\nThe user " +username+ " is not present in Privileged user group!"
            print "\nExiting script execution!"
            exit(1)

    elif getpass.getuser() != "root":
        print "\nUse 'sudo' to use super user privileges!"
        print "\nExiting script execution!!"
        exit(1)

    else:
        getpass.getuser() == "root"
        print "\nThe script is being executed as root user!"

except IOError:
    print "Script exited abnormally!"

if __name__ == '__main__':
    user_verification()
