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
# Name    : set_maxauthtries.py
# Purpose : This script configures sshd file by setting maxauthtries to 4
# Date    : 28-06-2021
# Author  : xoohran
# Revision : A
# Reason  : EQEV: 90004
# ********************************************************************
"""
import subprocess
import os
import getpass
import time
import logging

from sentinel_hardening import log_func
from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification

def set_maxauth():
    """This function configures the maxauthtries parameter to 4\
 in sshd_config file"""
    sshd_config = '/etc/ssh/sshd_config'
    backup_files(sshd_config, [])
    flag = 0
    fin = open(sshd_config, 'r')
    filecontent = fin.read()
    fin.close()
    try:
        if filecontent.find('MaxAuthTries 6') != -1:
            filecontent = filecontent.replace("#MaxAuthTries 6", "MaxAuthTries 4")
            flag = 1
        elif filecontent.find('MaxAuthTries 4') != -1:
            print "\n**********MaxAuthTries value for SSH communication\
 has already been configured on the server *********\n"
            logging.info('MaxAuthTries value is already set')
        elif filecontent.find('#MaxAuthTries 6') != 0:
            print "\n**********Script exits as default parameter is not found *********\n"
            logging.warning('Default parameter is not found')
        else:
            filecontent = filecontent +"\nMaxAuthTries 4"
            flag = 1
        if flag == 1:
            fout = open(sshd_config, 'w')
            fout.write(filecontent)
            fout.close()
            print "\n**********Successfully configured the MaxAuthTries\
 for SSH communication on the server**********\n"
            logging.info('Successfully set MaxAuthTries as "4"')
    except Exception:
        print "\nScript exited abnormally...!!!"
        logging.exception('Exited')
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_set_maxauthtries.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'set_maxauthtries.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        set_maxauth()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
