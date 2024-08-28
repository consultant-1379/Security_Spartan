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
# Name      : list_inactive_users.py
# Purpose   :This script lists the last login of all the users who has
#               the ssh login access. This is evaluated using the 'username'
#               file. Also it checks and lists all the users who have not
#               logged in for more than 90 days.
#Config File: username
# ********************************************************************
"""

import os
import subprocess
import time
import logging

from Verify_NH_Config import configure_nh
from user_verification import user_verification

USER_DATA = [subprocess.check_output('cat /ericsson/security/bin/username', shell=True)]

USER_DATA = USER_DATA[0].split("\n")
USER_DATA.pop()

def user_login():
    """This function lists all the users who have not logged in for more than 90 days"""
    print "**********Last login details of authorized users are logged under \
/ericsson/security/log/**********\n"
    logging.info('Last login details of authorized users were listed')
    for i in range(len(USER_DATA)):
        data = "last %s | sed '1!d'" % USER_DATA[i]
        var = [subprocess.check_output(data, shell=True)]
        if var[0] != '\n':
            logging.info(var[0].replace('\n', ""))
        os.system("lastlog -b 90 | grep USER_DATA[i]")

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_list_inactive_users.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)

    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()

    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        user_login()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "\nScript logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
