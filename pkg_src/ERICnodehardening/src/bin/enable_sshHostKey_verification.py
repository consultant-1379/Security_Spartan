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
# Name      : enable_sshHostKey_verification.py
# Purpose   : This script sets the permission to ssh host key to
#             detect attacks based on DNS or IP spoofing
#
# Config File: username
#
# ********************************************************************
"""
import os
import logging
import time
import subprocess

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification
file_name = "/etc/ssh/ssh_config"

def enable_ssh_hostkey():
    """This script verify ssh host key permission in ssh_config file"""

    backup_files(file_name, [])
    flag1 = 0
    flag2 = 0
    fin = open(file_name, 'r')
    filedata = fin.read()
    fin.close()

    if filedata.find('Verifyhostkeydns yes') != -1:
        filedata = filedata.replace("Verifyhostkeydns yes", "Verifyhostkeydns ask")
        flag1 = 1
    elif filedata.find('Verifyhostkeydns no') != -1:
        filedata = filedata.replace("Verifyhostkeydns no", "Verifyhostkeydns ask")
        flag1 = 1
    elif filedata.find('Verifyhostkeydns ask') == -1:
        filedata = filedata +"\nVerifyhostkeydns ask"
        flag1 = 1

    if filedata.find('stricthostkeychecking yes') != -1:
        filedata = filedata.replace("stricthostkeychecking yes", "stricthostkeychecking ask")
        flag2 = 1
    elif filedata.find('stricthostkeychecking no') != -1:
        filedata = filedata.replace("stricthostkeychecking no", "stricthostkeychecking ask")
        flag2 = 1
    elif filedata.find('stricthostkeychecking ask') == -1:
        filedata = filedata +"\nstricthostkeychecking ask"
        flag2 = 1
    if flag1 == 1 or flag2 == 1:
        f = open(file_name, 'w')
        f.write(filedata)
        f.close()
        print "\n**********Successfully enabled ssh host and key dns verification**********\n"
        logging.info('Successfully enabled ssh host and key dns verification')
    else:
        print "\n*********ssh host and key verification is already enabled on the server*********\n"
        logging.info('ssh host and key verification is already enabled on the server')

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_ssh_hostKey.log'
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
        print "\n\033[93mEnabling sshHostKey_verification\033[00m\n"
        enable_ssh_hostkey()
    else:
        print "Failed to verify the security settings. Execute \
/ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
