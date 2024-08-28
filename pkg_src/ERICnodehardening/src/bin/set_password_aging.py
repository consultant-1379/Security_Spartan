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
# *******************************************************************
# Name      : set_password_aging.py
# Purpose   : This script sets the password aging for all the users
#             except root and dcuser.
#*******************************************************************
"""

import os
import time
import logging
import subprocess

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification

def pass_age():
    """This function sets the password aging for all the users except \
root,dcuser,storobs and storobj"""

    try:
        backup_files("/etc/login.defs", [])
        with open("/etc/passwd", "r") as fin:
            data = fin.readlines()

        for i in data:
            if i != '\n':
                data1 = i.split(":")
                restore_aging(data1[0])
                if (data1[0] != "dcuser") and (data1[0] != "root") and (data1[0] != "storadm") and \
(data1[0] != "storobs") and (int(data1[2]) > 999):
                    com = "chage -M 60 " + data1[0]
                    war = "chage -W 7 " + data1[0]
                    os.system(com)
                    os.system(war)

        with open('/etc/login.defs') as fin:
            newtext = fin.read()
        if 'PASS_MAX_DAYS\t99999\n' in newtext:
            newtext = newtext.replace('PASS_MAX_DAYS\t99999\n', 'PASS_MAX_DAYS\t60\n')
        with open('/etc/login.defs', 'w') as fout:
            fout.write(newtext)
    except Exception:
        logging.info("Error while setting password aging")
    print"\n**********Password aging has been set to 60 days for all users, \
except root,dcuser,storadm and storobs!**********\n"
    logging.info('Password aging has been set to 60 days for all users \
except root,dcuser,storadm and storobs')

def restore_aging(user):
    """This function is to restore password aging for default users"""
    try:
        if user == "root" or user == "dcuser" or user == "storadm" or user =="storobs":
            age = subprocess.check_output("chage -l "+user,shell=True)
            age = age.split("\n")
            check_value = "Maximum number of days between password change\t\t: 60"
            if check_value in age:
                com = "chage -M 99999 " + user
                os.system(com)
    except subprocess.CalledProcessError:
        logging.info("Unable to restore the password aging to default")

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_password_aging.log'
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
        pass_age()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
