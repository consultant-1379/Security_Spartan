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
# Name      : enforce_selinux.py
# Purpose   : This script checks the status of SELinux and enforces
#              the same if it is in permissive or in disabled state.
#
# ********************************************************************
"""

import logging
import subprocess
import os
import re
import time

from NH_Backup import backup_files
from user_verification import user_verification

flag = None
#------------------------------------------------------------------------------------
#SELinux
#------------------------------------------------------------------------------------

def check_se_status():
    """This function enforces selinux if it is in permissive mode"""

    backup_files('/etc/selinux/config', [])
    status = subprocess.check_output("getenforce")

    if status == 'Permissive\n' or status == 'disabled\n':
        os.system("setenforce 1")
        print "\n**********Successfully enforced SELinux!**********\n"
        logging.info('Successfully enforced SELinux!')
        config_status = update_seconfig(flag)
        logging.info(config_status)
    else:
        config_status = update_seconfig(flag)
        if config_status == 'set':
            print "\n**********Successfully enforced SELinux!**********\n"
            logging.info("SELinux configuration has been updated in the \
'/etc/selinux/config' file.")
        elif config_status == None:
            print "\n**********SELinux is already enforced!**********\n"
            logging.info('SELinux is already enforced!')

def update_seconfig(flag):
    """This function updates the selinux config file"""
    config_file = open("/etc/sysconfig/selinux", "r")

    for line in config_file:
        if re.match("SELINUX=permissive|SELINUX=disabled", line):
            with open('/etc/sysconfig/selinux') as fin:
                newtext = fin.read().replace('SELINUX=permissive', 'SELINUX=enforcing').replace\
('SELINUX=disabled', 'SELINUX=enforcing')
            with open('/etc/sysconfig/selinux', "w") as fin:
                fin.write(newtext)
            flag = 'set'
    return flag

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_enforce_selinux.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)

#    print "\n\033[93mVerifying the security settings...\033[00m\n"
#    configure_NH()

#    STATUS = subprocess.check_output("echo $?", shell=True)
#    if STATUS == '0\n':
#        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
    check_se_status()
#    else:
#        print "Failed to verify the security settings. Execute \
#/ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
