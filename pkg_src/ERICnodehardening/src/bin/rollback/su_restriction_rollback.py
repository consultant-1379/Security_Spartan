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
# Name      : su_restriction_rollback.py
# Purpose   : This script rolls back su restriction.
# Author    : ZKATSHR
# Reason    : EQEV-115473
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

def rollback_su_restriction():
    """This function rolls back su restriction to its default state"""
    try:
        data=subprocess.check_output("cat /etc/pam.d/su | grep -e 'group=sugroup'", \
shell=True, stderr=subprocess.PIPE)
        if 'group=sugroup' in data :
            print"\nApplying rollback for su restriction. . . . . .\n"
            logging.info('Applying rollback for su restriction\n')
            with open('/etc/pam.d/su', 'r') as fin:
                newtext = fin.read()
            if 'group=sugroup' in newtext:
                newtext = newtext.replace('auth            required        \
pam_wheel.so use_uid group=sugroup' , '#auth           required        pam_wheel.so use_uid')
                os.system("groupdel sugroup")
            with open('/etc/pam.d/su', 'w') as fout:
                fout.write(newtext)
                fout.close()
            print "\nSuccessfully rolled back su restrcion\n"
            logging.info('Successfully rolled back su restrcion\n')
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for the feature\n"
        logging.info('Granular Node Hardening not detected for feature\n')

def checking_latestlog():
    """This function check the latest logs and compares"""
    try:
        granular_nh_logs_date_stamp = subprocess.check_output("ls -lrt /ericsson/security/log/ \
| grep su_restriction.log | tail -1 | cut -d ' ' -f 10 | cut -c '1-8'", shell=True, stderr=subprocess.PIPE)
        granular_nh_logs_time_stamp = subprocess.check_output("ls -lrt /ericsson/security/log/ \
| grep su_restriction.log | tail -1 | cut -d ' ' -f 10 | cut -c '10-15'", shell=True, stderr=subprocess.PIPE)
        rollback_logs_date_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        rollback_logs_time_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        if granular_nh_logs_date_stamp > rollback_logs_date_stamp:
            rollback_su_restriction()
        elif granular_nh_logs_date_stamp < rollback_logs_date_stamp:
            print"\nGranular Node Hardening for the feature is not applied\n"
            logging.info('Granular Node Hardening for the feature is not applied\n')
        elif granular_nh_logs_date_stamp == rollback_logs_date_stamp and \
granular_nh_logs_time_stamp > rollback_logs_time_stamp:
            rollback_su_restriction()
        elif granular_nh_logs_time_stamp < rollback_logs_time_stamp:
            print"\nGranular Node Hardening is not applied\n"
            logging.info('Granular Node Hardening is not applied\n')
        else:
            print"\nGranular Node Hardening is not applied for the feature\n"
            logging.info('Granular Node Hardening is not applied for the feature\n')
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for the feature\n"
        logging.info('Granular Node Hardening not detected for feature\n')

def checking_latestlog_new():
    """This function check the latest logs and compares"""
    try:
        granular_nh_logs_date_stamp_new = subprocess.check_output("ls -lrt /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep su_restriction.log | tail -1 | cut -d ' ' -f 10 \
| cut -c '1-8'", shell=True, stderr=subprocess.PIPE)
        granular_nh_logs_time_stamp_new = subprocess.check_output("ls -lrt /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep su_restriction.log | tail -1 | cut -d ' ' -f 10 \
| cut -c '9-15'", shell=True, stderr=subprocess.PIPE)
        rollback_logs_date_stamp_new = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        rollback_logs_time_stamp_new = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        if granular_nh_logs_date_stamp_new > rollback_logs_date_stamp_new:
            rollback_su_restriction()
        elif granular_nh_logs_date_stamp_new < rollback_logs_date_stamp_new:
            print"\nGranular Node Hardening for the feature is not applied\n"
            logging.info('Granular Node Hardening for the feature is not applied\n')
        elif granular_nh_logs_date_stamp_new == rollback_logs_date_stamp_new and \
granular_nh_logs_time_stamp_new > rollback_logs_time_stamp_new:
            rollback_su_restriction()
        elif granular_nh_logs_time_stamp_new < rollback_logs_time_stamp_new:
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
            data = subprocess.check_output("ls -lrt /ericsson/security/log/ | grep su_restriction \
| tail -1",shell=True, stderr=subprocess.PIPE).split()
            new = subprocess.check_output("ls -lrt /ericsson/security/log/Apply_NH_Logs/Manual_Exec/ \
| grep su_restriction.log | tail -1",shell=True, stderr=subprocess.PIPE).split()
            if not data and not new:
                print"\nGranular Node Hardening log is not \
present for su restriction \n"
                logging.info('Granular Node Hardening log is not \
present for su restriction\n')
            elif  data and  new :
                print"\nGranular Node Hardening log is present for su restriction\n"
                logging.info('Granular Node Hardening log is present for su restriction\n')
                checking_latestlog_new()
            elif data:
                print"\nGranular Node Hardening log is present for su restriction\n"
                logging.info('Granular Node Hardening log is present for su restriction\n')
                checking_latestlog()
            elif new:
                print"\nGranular Node Hardening log is present for su restriction\n"
                logging.info('Granular Node Hardening log is present for su restriction\n')
                checking_latestlog_new()
            else:
                print"\nGranular Node Hardening is not applied for the feature\n"
                logging.info('Granular Node Hardening is not applied for the feature\n')
        elif nh_check() == 1:
            print"\n******Full Node Hardening is applied on the \
server, rollback can not be applied******\n"
            logging.info('Full Node Hardening is applied on the server\n')
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for su restriction \n"
        logging.info('Granular Node Hardening not detected for su restriction\n')

if __name__ == "__main__":

    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_su_restriction_rollback.log'
    os.system("mkdir -p /ericsson/security/log/Manual_rollback_Exec/")
    FORMAT_STRING = '\n%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
filename="/ericsson/security/log/Manual_rollback_Exec/%s"\
% FNAME,format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME
    SCRIPT_NAME = 'su_restriction_rollback.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    log_file_presence()
    log_func(SCRIPT_NAME, 1, LOG_PATH)