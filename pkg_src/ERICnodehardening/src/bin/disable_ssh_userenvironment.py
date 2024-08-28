#!/usr/bin/python

"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2022 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : disable_ssh_userenvironment.py
# Purpose   : This script is to ensure SSH permit user environment is
#             disabled.
# Author    : ZBARPHU
# Reason    : EQEV-96572
# Revision  : A
# ********************************************************************
"""

import subprocess
import os
import time
import logging
import getpass

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from sentinel_hardening import log_func
from user_verification import user_verification

def disable_ssh_userenvironment():
    """This function is to ensure SSH permit user environment is disabled."""

    sshd_config = '/etc/ssh/sshd_config'
    backup_files(sshd_config, [])

    try:
        with open(sshd_config, 'r') as file:
            lines = file.readlines()

        with open(sshd_config, 'w') as file:
            for line in lines:
                line1 = line.strip("\n")
                if line1.find('#PermitUserEnvironment') == -1:
                    file.write(line)

        with open(sshd_config, 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        if 'PermitUserEnvironment no' not in data:
            if 'PermitUserEnvironment yes' in data:
                logging.warning('Customized value found!!')
            else:
                os.system("echo PermitUserEnvironment no >> /etc/ssh/sshd_config")
                print "\n**********Successfully ensured SSH permit user environment is \
disabled!**********\n"
                logging.info('Successfully ensured SSH permit User environment is \
disabled!!')
        elif 'PermitUserEnvironment no' in data:
            print "\n**********Already ensured SSH permit user environment is \
disabled!**********!\n"
            logging.warning('Already ensured SSH permit user environment is disabled!!')
        else:
            logging.warning('Customized value found!!')
    except IOError:
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_disable_ssh_userenvironment.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'disable_ssh_userenvironment.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        disable_ssh_userenvironment()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
