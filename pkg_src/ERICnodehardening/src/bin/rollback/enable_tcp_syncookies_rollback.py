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
# Name      : enable_tcp_syncookies_rollback.py
# Purpose   : This script rolls back tcp syn cookies.
# Author    : ZKATSHR
# Reason    : EQEV-131365
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

def rollback_tcp_syncookies():
    """"This function sets the tcp syn cookies value to its default state"""
    try:
        line = subprocess.check_output("cat /etc/sysctl.conf ", shell=True, stderr=subprocess.PIPE)
        if 'net.ipv4.tcp_syncookies=0' in line:
            print"\nCustomized value found\n"
            logging.info("Customized value found\n")
        elif 'net.ipv4.tcp_syncookies=1' not in line:
            print"\nGranular Node Hardening is not applied for tcp syn cookies\n"
            logging.info('Granular Node Hardening is not applied for tcp syn cookies\n')
        elif 'net.ipv4.tcp_syncookies=1' in line:
            os.system("sed -i '/net.ipv4.tcp_syncookies=1/d' /etc/sysctl.conf")
            print"\nSuccessfully tcp syn cookies has been rolled back\n"
            logging.info('Successfully tcp syn cookies has been rolled back\n')
    except (subprocess.CalledProcessError, OSError):
        logging.warning("Granular Node Hardening is not detected for tcp syn cookies")

def checking_latestlog():
    """This function check the latest logs and compares"""
    try:
        granular_nh_logs_date_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep enable_tcp_syncookies  | sort -n | tail -1 \
| cut -d '/' -f 7 | cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        granular_nh_logs_time_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep enable_tcp_syncookies  | sort -n | tail -1 | cut -d '/' -f 7 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        rollback_logs_date_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        rollback_logs_time_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        if granular_nh_logs_date_stamp > rollback_logs_date_stamp:
            rollback_tcp_syncookies()
        elif granular_nh_logs_date_stamp < rollback_logs_date_stamp:
            print"\nGranular Node Hardening for the feature is not applied\n"
            logging.info('Granular Node Hardening for the feature is not applied\n')
        elif granular_nh_logs_date_stamp == rollback_logs_date_stamp and \
granular_nh_logs_time_stamp > rollback_logs_time_stamp:
            rollback_tcp_syncookies()
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
    """This function checks whether granular log for particular feature is present or not"""
    try:
        if nh_check() == 0:
            data = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep enable_tcp_syncookies | sort -n \
| tail -1",shell=True, stderr=subprocess.PIPE).split()
            if not data:
                print"\nGranular Node Hardening log is not \
present for tcp syn cookies\n"
                logging.info('Granular Node Hardening log is not \
present for tcp syn cookies\n')
            else:
                checking_latestlog()
        elif nh_check() == 1:
            print"\n******Full Node Hardening is applied on the \
server, rollback can not be applied******\n"
            logging.info('Full Node Hardening is applied on the server\n')
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for tcp syn cookies \n"
        logging.info('Granular Node Hardening not detected for tcp syn cookies\n')

if __name__ == "__main__":
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_enable_tcp_syncookies_rollback.log'
    os.system("mkdir -p /ericsson/security/log/Manual_rollback_Exec/")
    FORMAT_STRING = '\n%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
filename="/ericsson/security/log/Manual_rollback_Exec/%s"\
% FNAME,format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME
    SCRIPT_NAME = 'enable_tcp_syncookies_rollback.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    log_file_presence()
    log_func(SCRIPT_NAME, 1, LOG_PATH)