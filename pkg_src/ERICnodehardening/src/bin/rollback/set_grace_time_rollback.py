#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2023 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : set_grace_time_rollback.py
# Purpose   : This script resets grace time to its default value.
# Author    : ZKATSHR
# Reason    : EQEV-115470
# ********************************************************************
"""
import os
import logging
import subprocess
import time
import sys
sys.path.insert(0, '/ericsson/security/bin')

from nh_verification import nh_check
from user_verification import user_verification
from sentinel_hardening import log_func
from Verify_NH_Config import configure_nh

def replace_gracetime():
    """This function sets the grace time to 2 minute."""
    try:
        file_name = "/etc/ssh/sshd_config"
        data=subprocess.check_output("cat /etc/ssh/sshd_config | grep LoginGraceTime", \
shell=True, stderr=subprocess.PIPE).strip()
        if "LoginGraceTime 1m" in data :
            print"\nApplying rollback on LoginGracetime\n"
            logging.info('Applying rollback on LoginGracetime\n')
            with open(file_name) as fin:
                newtext = fin.read().replace('LoginGraceTime 1m', '#LoginGraceTime 2m')
            with open(file_name, "w") as fin:
                fin.write(newtext)
                fin.close()
            print"\nSuccessfully applied rollback on LoginGracetime\n"
            logging.info('Successfully applied rollback on LoginGracetime\n')
        elif "#LoginGraceTime 2m" in data:
            print"\nGranular Node Hardening is not applied for the feature\n"
            logging.info('Granular Node Hardening is not applied for the feature\n')
        elif "LoginGraceTime 1m" not in data and "#LoginGraceTime 2m" not in data :
            print"\nCustomize value found, we can not rollback\n"
            logging.info('Customize value found, we can not rollback\n')
        elif "LoginGraceTime" != "loginGraceTime":
            print"\nCustomize value found, we can not rollback \n"
            logging.info('Customize value found, we can not rollback \n')
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for the feature\n"
        logging.info('Granular Node Hardening not detected for feature\n')

def checking_latestlog():
    """This function check the latest logs and compares"""
    try:
        granular_nh_logs_date_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep set_grace_time  | sort -n | tail -1 \
| cut -d '/' -f 7 | cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        granular_nh_logs_time_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep set_grace_time  | sort -n | tail -1 | cut -d '/' -f 7 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        rollback_logs_date_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        rollback_logs_time_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        if granular_nh_logs_date_stamp > rollback_logs_date_stamp:
            replace_gracetime()
        elif granular_nh_logs_date_stamp < rollback_logs_date_stamp:
            print"\nGranular Node Hardening for the feature is not applied\n"
            logging.info('Granular Node Hardening for the feature is not applied\n')
        elif granular_nh_logs_date_stamp == rollback_logs_date_stamp and \
granular_nh_logs_time_stamp > rollback_logs_time_stamp:
            replace_gracetime()
        elif granular_nh_logs_time_stamp < rollback_logs_time_stamp:
            print"\nGranular Node Hardening is not applied\n"
            logging.info('Granular Node Hardening is not applied\n')
        else:
            print"\nGranular Node Hardening is not applied for the feature\n"
            logging.info('Granular Node Hardening is not applied for the feature\n')
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for the feature\n"
        logging.info('Granular Node Hardening not detected for feature\n')

def log_file_presence():
    """This function check whether granular log for particular feature is present or not"""
    try:
        if nh_check() == 0:
            data = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep set_grace_time | sort -n \
| tail -1",shell=True, stderr=subprocess.PIPE).split()
            if not data:
                print"\nGranular Node Hardening log is not \
present for LoginGracetime \n"
                logging.info('Granular Node Hardening log is not \
present for LoginGracetime\n')
            else:
                print"\nGranular Node Hardening log are present for LoginGracetime\n"
                logging.info('Granular Node Hardening log is present for LoginGracetime\n')
                checking_latestlog()
        elif nh_check() == 1:
            print"\n******Full Node Hardening is applied on the \
server, rollback can not be applied******\n"
            logging.info('Full Node Hardening is applied on the server\n')
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for LoginGracetime \n"
        logging.info('Granular Node Hardening not detected for LoginGracetime\n')

if __name__ == "__main__":

    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_set_grace_time_rollback.log'
    os.system("mkdir -p /ericsson/security/log/Manual_rollback_Exec/")
    FORMAT_STRING = '\n%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Manual_rollback_Exec/%s"\
                                                % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME
    SCRIPT_NAME = 'set_grace_time_rollback.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        log_file_presence()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)