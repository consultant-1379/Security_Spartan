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
# Name      : restrict_cron.py
# Purpose   : This script restricts the permission of users to
#               configure cron jobs.
#Config File: cron_conf
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
bckp_file = "/etc/cron.allow"

def cron():
    """This function restricts the permission of users to configure cron jobs."""

    with open('/ericsson/security/bin/cron_conf', 'r') as fin:
        data = fin.read()

    data = data.split('\n')

    for i in data:
        if 'Allow' in i:
            i = i.split()
            a = i[1:]
#        elif 'Deny' in i:
#            i = i.split()
#            d = i[1:]
    cmd1 = "[ -f /etc/cron.allow ] && echo 'File exist' || echo 'File does not exist' "
    result = subprocess.check_output(cmd1, shell=True)

    if result == 'File exist\n':
        backup_files(bckp_file, [])
        os.system("chmod 600 /etc/cron.allow")
        with open(bckp_file, 'w') as fin:
            fin.writelines('\n'.join(a)+'\n')
    else:
        cron_if_exist('cron_allow_config')
        fout = open(bckp_file, 'w+')
        os.system("chmod 600 /etc/cron.allow")
        fout.writelines('\n'.join(a)+'\n')
        fout.close()

#    Removing /etc/cron.deny in set_file_permissions.py
#
#    cmd1 = "[ -f /etc/cron.deny ] && echo 'File exist' || echo 'File does not exist' "
#    result = subprocess.check_output(cmd1, shell=True)

#    if result == 'File exist\n':
#        backup_files('/etc/cron.deny', [])
#        with open('/etc/cron.deny', 'w') as fin:
#            fin.writelines('\n'.join(d)+'\n')
#    else:
#        cron_if_exist('cron_deny_config')
#        fout = open('/etc/cron.deny', 'w+')
#        fout.writelines('\n'.join(d)+'\n')
#        fout.close()

    print "\n**********Successfully restricted user access and management for cron jobs\
**********\n"
    logging.info('Successfully restricted user access and management for cron jobs')

def cron_if_exist(file):
    """This is to check if /etc/cron.allow file exists or not in Backup directory"""
    if os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES") is True:
        if os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES/%s" % file) is False:
            os.system("touch /ericsson/security/BACKUP_CONFIG_FILES/%s" % file)
    else:
        os.system("mkdir -p /ericsson/security/BACKUP_CONFIG_FILES")
        os.system("touch /ericsson/security/BACKUP_CONFIG_FILES/%s" % file)

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_restrict_cron.log'
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
        cron()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
