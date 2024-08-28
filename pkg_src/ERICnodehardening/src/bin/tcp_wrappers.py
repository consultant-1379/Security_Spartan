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
# Name      : tcp_wrappers.py
# Purpose   : This script sets the permission to access network
#               services to specific users
#
# ********************************************************************
"""
import os
import time
import logging
import subprocess

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification
file_name = "/etc/hosts.deny"

def tcp_wrap():
    """This function sets the permission to access network services to specific users"""

    cmd = "[ -f /etc/hosts.allow ] && echo 'File exist' || echo 'File does not exist' "
    result = subprocess.check_output(cmd, shell=True)
    f = 0
    if result == 'File exist\n':
        backup_files('/etc/hosts.allow', [])
    else:
        hosts_if_exist('hosts_allow_config')
        subprocess.call("touch /etc/hosts.allow", shell=True)

    cmd1 = "[ -f /etc/hosts.deny ] && echo 'File exist' || echo 'File does not exist' "
    result = subprocess.check_output(cmd1, shell=True)

    if result == 'File exist\n':
        backup_files(file_name, [])
        with open(file_name, 'r') as fin:
            data = fin.readlines()
        for i in data:
            if i == 'vsftpd: ALL\n':
                f = 1
                print "\n**********vsftpd access is already restricted for all users*********\n"
                logging.warning('vsftpd access is already restricted for all users')
        if f != 1:
            data.append('vsftpd: ALL\n')
            with open(file_name, 'w') as fout:
                fout.writelines(''.join(data))
            print "\n**********Successfully disabled vsftpd access for all the users**********\n"
            logging.info('Successfully disabled vsftpd for all the users')
    else:
        hosts_if_exist('hosts_deny_config')
        subprocess.call("echo vsftpd: ALL >> /etc/hosts.deny", shell=True)
        print "\n**********vsftpd has been disabled for all users**********\n"
        logging.info('vsftpd has been disabled for all users')

def hosts_if_exist(file):
    """This function is to verify if the hosts file exists"""
    if os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES") is True:
        if os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES/%s" % file) is False:
            os.system("touch /ericsson/security/BACKUP_CONFIG_FILES/%s" % file)
    else:
        os.system("mkdir -p /ericsson/security/BACKUP_CONFIG_FILES")
        os.system("touch /ericsson/security/BACKUP_CONFIG_FILES/%s" % file)

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_tcp_wrappers.log'
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
        tcp_wrap()
    else:
        print "Failed to verify the security settings. Execute \
/ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \033[93m/ericsson/security/log/Apply_NH_Logs/\
Manual_Exec/\033[00m directory!"
