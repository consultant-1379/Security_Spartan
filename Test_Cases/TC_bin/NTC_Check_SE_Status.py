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
# ******************************************************************************
# Name      : NTC_Check_SE_Status.py
# Purpose   : This script checks w negative test case scenario 
#             by disabling SeLinux.
#
#
# ******************************************************************************
"""



import time
import logging
import subprocess as s
import os
import commands as c
import re
from TC_Check_SE_Status import TC_se

flag = None
def set_se_status():

    """This function removes selinux if it is in enforcing mode"""

    status = s.check_output("getenforce")

    if status == 'Enforcing\n':
        os.system("setenforce 0")
        print "\n**********Successfully removed SELinux!**********\n"
        logging.info('Successfully removed SELinux!')
        config_status = update_seconfig(flag)
    else:
        config_status = update_seconfig(flag)
        if config_status == 'reset':
            logging.info("SELinux configuration has been updated in the '/etc/selinux/config' file.")

def update_seconfig(flag):
    config_file = open("/etc/sysconfig/selinux", "r")

    for line in config_file:
        if re.match("SELINUX=enforcing", line):
            with open('/etc/sysconfig/selinux') as fin:
                newText = fin.read().replace('SELINUX=enforcing','SELINUX=permissive')
            with open('/etc/sysconfig/selinux', "w") as fin:
                fin.write(newText)
            flag = 'reset'
    return flag


def NTC_se():
    set_se_status()

    status=TC_se()
    os.system("/ericsson/security/bin/enforce_selinux.py > /dev/null 2>&1")
    if status == "FAIL":
        return "SUCCESS"
    else:
        return "FAIL" 

if __name__ == "__main__":

    print NTC_se()

