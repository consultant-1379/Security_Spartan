#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
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
# ********************************************************************
# Name      : verify_ip_config.py
# Purpose   : This scripts is to list down the ip's which has not
#             been configured to any nic
# ********************************************************************
"""

import subprocess
import os

from Verify_NH_Config import configure_nh
from user_verification import user_verification
rm_cmd = "rm -rf some"

def ipconfig():
    """This function list down the ip's which has not been configured to any nic"""
    subprocess.call("ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' \
| cut -f1  -d'/' > some", shell=True)
    with open("./some", 'r') as fin:
        data1 = fin.read()
    if data1:
        if data1[0].isalpha():
            print "Warning:Ethernet is assigned to server but ip address is not configured"
            os.system(rm_cmd)
        elif data1[0].isdigit():
            print '\n*********IP address is configured!*********\n'
            os.system(rm_cmd)
    else:
        print "\nIP address is not configured!\n"
        os.system(rm_cmd)

if __name__ == '__main__':
    user_verification()
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()

    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        ipconfig()
    else:
        print "Failed to verify the security settings. Execute \
/ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
