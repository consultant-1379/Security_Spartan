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
# Name      : enable_ignoreRhosts.py
# Purpose   : This script ensures that SSH IgnoreRhosts is enabled.
# Author    : ZATLPOE
# Reason    : EQEV-96568
# Revision  : A
# ********************************************************************
"""
import subprocess
import os
import time
import logging
import getpass

from Verify_NH_Config import configure_nh
from sentinel_hardening import log_func
from NH_Backup import backup_files
from user_verification import user_verification

def enable_ignorerhosts():
    """This function ensure that SSH IgnoreRhosts is enabled."""

    backup_files('/etc/ssh/sshd_config', [])

    try:
        with open("/etc/ssh/sshd_config") as fin:
            data = fin.read()
        data = data.split('\n')
        newconfig = ""
        with open("/etc/ssh/sshd_config") as fin:
            if 'IgnoreRhosts no' in data:
                logging.warning('Customized value found!')
            elif 'IgnoreRhosts yes' not in data:
                if '#IgnoreRhosts yes' in data:
                    newconfig = fin.read().replace('#IgnoreRhosts yes', 'IgnoreRhosts yes')
                    print "\n**********Successfully ensure SSH IgnoreRhosts is enabled**********\n"
                    logging.info('Successfully ensure SSH IgnoreRhosts is enabled\n')
                elif '#IgnoreRhosts no' in data:
                    newconfig = fin.read().replace('#IgnoreRhosts no', 'IgnoreRhosts yes')
                    print "\n**********Successfully ensure SSH IgnoreRhosts is enabled**********\n"
                    logging.info('Successfully ensure SSH IgnoreRhosts is enabled\n')
                else:
                    os.system("echo IgnoreRhosts yes >> /etc/ssh/sshd_config")
                    print "\n**********Successfully ensure SSH IgnoreRhosts is enabled**********\n"
                    logging.info('Successfully ensure SSH IgnoreRhosts is enabled\n')
            elif 'IgnoreRhosts yes' in data:
                print "\n**********Already ensure SSH IgnoreRhosts is enabled**********\n"
                logging.info('Already ensure SSH IgnoreRhosts is enabled\n')

        if newconfig:
            with open("/etc/ssh/sshd_config", "w") as fout:
                fout.write(newconfig)
    except IOError:
        logging.error('Script exited abnormally')

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_enable_ignoreRhosts.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'enable_ignoreRhosts.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        enable_ignorerhosts()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
