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
# Name      : restrict_cron_rollback.py
# Purpose   : This script resets the restrict cron to its default value.
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

def rollback_restrict_cron():
    """This function is to set the restrict cron to its default state"""
    try:
        file_name = '/etc/cron.allow'
        if not os.path.exists(file_name):
            print"\nGranular Node Hardening is not applied for the feature\n"
            logging.info('Granular Node Hardening is not applied for the feature\n')
        else :
            print"\nApplying rollback on restrict cron feature\n"
            logging.info('Applying rollback on restrict cron feature\n')
            os.system("rm -rf /etc/cron.allow")
            print "\nSuccessfully rolled back the restrict cron feature\n"
            logging.info ('Successfully rolled back the restrict cron feature\n')
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for restrict cron feature \n"
        logging.info('Granular Node Hardening not detected for restrict cron feature\n')

def checking_latestlog():
    """This function check the latest logs and compares"""
    try:
        granular_nh_logs_date_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep restrict_cron  | sort -n | tail -1 \
| cut -d '/' -f 7 | cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        granular_nh_logs_time_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep restrict_cron | sort -n | tail -1 | cut -d '/' -f 7 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        rollback_logs_date_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        rollback_logs_time_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        if granular_nh_logs_date_stamp > rollback_logs_date_stamp:
            rollback_restrict_cron()
        elif granular_nh_logs_date_stamp < rollback_logs_date_stamp:
            print"\nGranular Node Hardening for the feature is not applied\n"
            logging.info('Granular Node Hardening for the feature is not applied\n')
        elif granular_nh_logs_date_stamp == rollback_logs_date_stamp and \
granular_nh_logs_time_stamp > rollback_logs_time_stamp:
            rollback_restrict_cron()
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
log/Apply_NH_Logs/Manual_Exec/ | grep restrict_cron | sort -n \
| tail -1",shell=True, stderr=subprocess.PIPE).split()
            if not data:
                print"\nGranular Node Hardening log is not \
present for restrict cron feature\n"
                logging.info('Granular Node Hardening log is not \
present for restrict cron feature\n')
            else:
                print"\nGranular Node Hardening log are present for restrict cron feature\n"
                logging.info('Granular Node Hardening log is present for restrict cron feature\n')
                checking_latestlog()
        elif nh_check() == 1:
            print"\n******Full Node Hardening is applied on the \
server, rollback can not be applied******\n"
            logging.info('Full Node Hardening is applied on the server\n')
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for restrict cron feature \n"
        logging.info('Granular Node Hardening not detected for restrict cron feature\n')
if __name__ == "__main__":
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_restrict_cron_rollback.log'
    os.system("mkdir -p /ericsson/security/log/Manual_rollback_Exec/")
    FORMAT_STRING = '\n%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Manual_rollback_Exec/%s"\
 % FNAME,format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME
    SCRIPT_NAME = 'restrict_cron_rollback.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    log_file_presence()
    log_func(SCRIPT_NAME, 1, LOG_PATH)