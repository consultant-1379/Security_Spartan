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
# Name      : set_inactive_days.py
# Purpose   : This script sets the Inactive User Account lock for all
#             users present on system except root and storadm.
# Author    : Pradeep Kumar Doddagoudar
# ZID       : ZDODPRA
# Date      : 11-06-2021
# Revision  : A
# Reason    : EQEV-88190
# ********************************************************************
# History
"""
import os
import subprocess
import time
import logging
import getpass
from Verify_NH_Config import configure_nh
from sentinel_hardening import log_func
from user_verification import user_verification
def set_inactive():
    """This is to set inactive password lock """
    status_default = set_default()
    if status_default == "already_enabled":
        print"\n************Inactive Account Lock is already\
 enforced as 30 days by default*************\n"
        logging.info("Inactive Account Lock is already enforced as 30 days by default.")
    else:
        status_users = set_users()
        if status_default and status_users:
            print"\n*************Inactive User Account Lock has been successfully \
enabled*************\n"
            logging.info("*************Inactive User Account Lock has been successfully \
enabled*************")
    os.system("rm -rf /ericsson/security/bin/inactive_days.txt")
def set_default():
    """This function sets inactive password lock as 30 days by default"""
    inactive_days = subprocess.check_output("useradd -D | grep INACTIVE", shell=True)
    if inactive_days != "INACTIVE=30\n":
        return_value = os.system("useradd -D -f 30")
        if return_value != 0:
            print "Unable to set inactive password lock as 30 days by default."
            logging.error("Unable to set inactive password lock as 30 days by default.")
            return False
        else:
            logging.info("Set the inactive password lock as 30 days by default.")
    else:
        return "already_enabled"
    return True
def set_users():
    """This function is to set inactive password lock to 30 day for present users"""
    return_value = os.system(r"grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,7 \
> /ericsson/security/bin/inactive_days.txt")
    if return_value != 0:
        logging.error("Unable to fetch user accounts and its inactive password lockout period")
    else:
        logging.info("Fetched user accounts and its inactive password lockout period")
    with open("/ericsson/security/bin/inactive_days.txt", 'r') as fin:
        data = fin.readlines()
    data1 = []
    for i in data:
        if i != "\n":
            data1 = i.split(':')
            if (data1[0] != "root") and (data1[0] != "storadm"):
                user = data1[0]
                return_value = os.system("chage --inactive 30 %s" %user)
                if return_value != 0:
                    logging.error("Unable to set inactive password lock as 30 days for users.")
                    return False
                else:
                    logging.info("Successfully set inactive password lock to 30 day \
for user %s" %user)
    return True
if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + 'set_inactive_days.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STR = '%(levelname)s:\t %(asctime)s:\t %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STR)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/"+FNAME
    SCRIPT_NAME = '_set_inactive_days.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        set_inactive()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
