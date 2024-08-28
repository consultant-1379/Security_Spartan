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
# Name      : restrict_at.py
# Purpose   : This script restricts the permission of users to
#               configure at jobs.
# Config File: at_conf
#
# ********************************************************************
"""
import subprocess
import os
import time
import logging

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification
bckp_file_allow = "/etc/at.allow"
bckp_file_deny = "/etc/at.deny"

def at():
    """This function restricts the permission of users to configure at jobs."""

    with open('/ericsson/security/bin/at_conf', 'r') as fin:
        data = fin.read()

    data = data.split('\n')

    for i in data:
        if 'Allow' in i:
            i = i.split()
            a = i[1:]
        elif 'Deny' in i:
            i = i.split()
            d = i[1:]
    cmd1 = "[ -f /etc/at.allow ] && echo 'File exist' || echo 'File does not exist' "
    result = subprocess.check_output(cmd1, shell=True)

    if result == 'File exist\n':
        backup_files(bckp_file_allow, [])
        os.system("chmod 600 /etc/at.allow")
        with open(bckp_file_allow, 'w') as fin:
            fin.writelines('\n'.join(a))
    else:
        at_if_exist('at_allow_config')
        fout = open(bckp_file_allow, 'w+')
        os.system("chmod 600 /etc/at.allow")
        fout.writelines('\n'.join(a))
        fout.close()

    cmd1 = "[ -f /etc/at.deny ] && echo 'File exist' || echo 'File does not exist' "
    result = subprocess.check_output(cmd1, shell=True)
    if result == 'File exist\n':
        backup_files(bckp_file_deny, [])
        os.system("chmod 600 /etc/at.deny")
        with open(bckp_file_deny, 'w') as fin:
            fin.writelines('\n'.join(d))
    else:
        at_if_exist('at_deny_config')
        fout = open(bckp_file_deny, 'w+')
        os.system("chmod 600 /etc/at.deny")
        fout.writelines('\n'.join(d))
        fout.close()

    print "\n**********Successfully restricted user access and \
management for 'at' command**********\n"
    logging.info("Successfully restricted user access and management for 'at' command")

def at_if_exist(file):
    """This function defines the at conf fle it it exists"""
    if os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES") is True:
        if os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES/%s" % file) is False:
            os.system("touch /ericsson/security/BACKUP_CONFIG_FILES/%s" % file)
    else:
        os.system("mkdir -p /ericsson/security/BACKUP_CONFIG_FILES")
        os.system("touch /ericsson/security/BACKUP_CONFIG_FILES/%s" % file)

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_restrict_at.log'
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
        at()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \033[93m/ericsson/security/log/Apply_NH_Logs/\
Manual_Exec/\033[00m directory!"
