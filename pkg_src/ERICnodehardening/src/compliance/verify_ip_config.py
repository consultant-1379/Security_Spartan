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
# Name      : verify_ip_config.py
# Purpose   : This script verifies the ipconfig file on the system.
# ********************************************************************
"""

import os
import subprocess
rm = "rm -rf ip_config.txt"

def ipconfig_check():
    """This function checks for the ipconfig file"""
    subprocess.call("ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | \
cut -f1  -d'/' > ip_config.txt", shell=True)

    with open("./ip_config.txt", 'r') as r:
        data1 = r.read()
    if data1:
        string = ""
        if data1[0].isalpha():
            os.system(rm)
            string = "NOK"
        elif data1[0].isdigit():
            os.system(rm)
            string = "OK"
        else:
            string = "NOK"
        return string
    else:
        os.system(rm)
        return "NOK"

if __name__ == '__main__':
    ipconfig_check()
