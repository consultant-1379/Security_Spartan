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
# Name      : set_inactive_days_rollback.py
# Purpose   : This script resets inactive_days its default value.
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

def check_inactive_days():
    """This is to set inactive password lock """
    try:
        status_default = set_default()
        if status_default == "already_disabled":
            print"\nInactive Account Lock is already\
 enforced as -1 days by default\n"
            logging.info("Inactive Account Lock is already enforced as -1 \
days by default.")
        else:
            status_users = set_users()
            if status_default and status_users:
                print"\nInactive User Account Lock has been successfully \
disabled\n"
                logging.info("Inactive User Account Lock has been successfully \
disabled")
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for the inactive password lock\n"
        logging.info('Granular Node Hardening not detected for the inactive password lock\n')

def set_default():
    """This function sets inactive password lock as -1 days by default"""
    try:
        inactive_days = subprocess.check_output("useradd -D | grep INACTIVE", shell=True)
        if inactive_days != "INACTIVE=-1\n":
            os.system("useradd -D -f -1")
            logging.info("Set the inactive password lock as -1 days by default.")
        else:
            return "already_disabled"
        return True
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for inactive password lock\n"
        logging.info('Granular Node Hardening not detected for inactive password lock\n')

def set_users():
    """This function is to set inactive password lock to -1 day for present users"""
    try:
        os.system(r"grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,7 \
> /ericsson/security/bin/inactive_days.txt")
        logging.info("Fetched user accounts and its inactive password lockout period")
        with open("/ericsson/security/bin/inactive_days.txt", 'r') as fin:
            data = fin.readlines()
        data1 = []
        for i in data:
            if i != "\n":
                data1 = i.split(':')
                if (data1[0] != "root") and (data1[0] != "storadm"):
                    user = data1[0]
                    return_value = os.system("chage --inactive -1 %s" %user)
                    if return_value != 0:
                        logging.error("Unable to set inactive password lock as -1 days for users.")
                        return False
                    else:
                        logging.info("Successfully set inactive password lock to -1 day \
for user %s" %user)
        return True
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for the feature\n"
        logging.info('Granular Node Hardening not detected for feature\n')

def checking_latestlog():
    """This function check the latest logs and compares"""
    try:
        granular_nh_logs_date_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep set_inactive_days | sort -n | tail -1 \
| cut -d '/' -f 7 | cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        granular_nh_logs_time_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep set_inactive_days | sort -n | tail -1 | cut -d '/' -f 7 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        rollback_logs_date_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        rollback_logs_time_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        if granular_nh_logs_date_stamp > rollback_logs_date_stamp:
            check_inactive_days()
        elif granular_nh_logs_date_stamp < rollback_logs_date_stamp:
            print"\nGranular Node Hardening for the feature is not applied\n"
            logging.info('Granular Node Hardening for the feature is not applied\n')
        elif granular_nh_logs_date_stamp == rollback_logs_date_stamp and \
granular_nh_logs_time_stamp > rollback_logs_time_stamp:
            check_inactive_days()
        elif granular_nh_logs_time_stamp < rollback_logs_time_stamp:
            print"\nGranular Node hardening is not applied\n"
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
log/Apply_NH_Logs/Manual_Exec/ | grep set_inactive_days | sort -n \
| tail -1",shell=True, stderr=subprocess.PIPE).split()
            if not data:
                print"\nGranular Node Hardening log is not \
present for setting inactive days\n"
                logging.info('Granular Node Hardening log is not \
present for setting inactive days\n')
            else:
                print"\nGranular Node Hardening log are present for setting inactive days\n"
                logging.info('Granular Node Hardening log is present for setting inactive days\n')
                checking_latestlog()
        elif nh_check() == 1:
            print"\n******Full Node Hardening is applied on the \
server, rollback can not be applied******\n"
            logging.info('Full Node Hardening is applied on the server\n')
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for setting inactive days\n"
        logging.info('Granular Node Hardening not detected for setting inactive days\n')

if __name__ == "__main__":
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_set_inactive_days_rollback.log'
    os.system("mkdir -p /ericsson/security/log/Manual_rollback_Exec/")
    FORMAT_STRING = '\n%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Manual_rollback_Exec/%s"\
% FNAME,format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME
    SCRIPT_NAME = 'set_inactive_days_rollback.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    log_file_presence()
    log_func(SCRIPT_NAME, 1, LOG_PATH)