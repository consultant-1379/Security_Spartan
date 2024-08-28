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
# Name      : set_file_permission_rollback.py
# Purpose   : This script sets file permission to default state.
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

def reset_permission():
    """This function sets default file permission after checking existence"""
    try:
        if os.path.exists('/sys/firmware/efi'):
            files_list = ["/etc/at.allow", "/etc/at.deny",
                          "/etc/cron.allow", "/etc/crontab"]
        else:
            files_list = ["/boot/grub2/grub.cfg", "/etc/at.allow",
                          "/etc/at.deny", "/etc/cron.allow", "/etc/crontab"]
        dir_list = ["/etc/cron.d", "/etc/cron.daily",
                    "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]
        status1 = reset_file_permission(files_list)
        status2 = reset_dir_permission(dir_list)
        if status1 and status2:
            print"\nSuccessfully reset the file permissions to it's default state\n"
            logging.info("Successfully reset the file permissions to it's default state\n")
        else:
            print"\nCannot reset the file permissions\n"
            logging.info("Cannot reset the file permissions\n")
    except IOError:
        print"\n Granular Node Hardening not detected for file permission \n"
        logging.info('Granular Node Hardening not detected for file permission\n')

def reset_file_permission(files_list):
    """This function is to set the default file permissions"""
    try:
        for files in files_list:
            if os.path.exists(files):
                os.system("chmod 644 "+files+"> /dev/null 2>&1")
                logging.info("Reset default permissions for the file "+files+" ")
            else:
                print "\nFile "+files+" not Exists\n"
                logging.info("File "+files+" doesn't exist\n")
    except (IOError, KeyboardInterrupt):
        log_func(script_name, 1, LOG_PATH)
        return False
    return True
def reset_dir_permission(dir_list):
    """This function is to set the default directory permissions"""
    try:
        for dirs in dir_list:
            if os.path.exists(dirs):
                os.system("chmod 755 "+dirs+"> /dev/null 2>&1")
                logging.info("Reset default permissions for the directory "+dirs+" \n ")
            else:
                print "\nDirectory "+dirs+" not Exists\n"
                logging.info("Directory "+dirs+" doesn't exist\n")
    except (IOError, KeyboardInterrupt):
        log_func(script_name, 1, LOG_PATH)
        return False
    return True


def checking_latestlog():
    """This function check the latest logs and compares"""
    try:
        granular_nh_logs_date_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep set_permission  | sort -n | tail -1 \
| cut -d '/' -f 7 | cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        granular_nh_logs_time_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep set_permission | sort -n | tail -1 | cut -d '/' -f 7 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        rollback_logs_date_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        rollback_logs_time_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        if granular_nh_logs_date_stamp > rollback_logs_date_stamp:
            reset_permission()
        elif granular_nh_logs_date_stamp < rollback_logs_date_stamp:
            print"\nGranular Node Hardening for the feature is not applied\n"
            logging.info('Granular Node Hardening for the feature is not applied\n')
        elif granular_nh_logs_date_stamp == rollback_logs_date_stamp and \
granular_nh_logs_time_stamp > rollback_logs_time_stamp:
            reset_permission()
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
log/Apply_NH_Logs/Manual_Exec/ | grep set_permission | sort -n \
| tail -1",shell=True, stderr=subprocess.PIPE).split()
            if not data:
                print"\nGranular Node Hardening log is not \
present for file permission \n"
                logging.info('Granular Node Hardening log is not \
present for file permission\n')
            else:
                print"\nGranular Node Hardening log is present for file permission\n"
                logging.info('Granular Node Hardening log is present for file permission\n')
                checking_latestlog()
        elif nh_check() == 1:
            print"\n******Full Node Hardening is applied on the \
server, rollback can not be applied******\n"
            logging.info('Full Node Hardening is applied on the server\n')
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for file permission \n"
        logging.info('Granular Node Hardening not detected for file permission\n')

if __name__ == "__main__":

    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_set_file_permission_rollback.log'
    os.system("mkdir -p /ericsson/security/log/Manual_rollback_Exec/")
    FORMAT_STRING = '\n%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
filename="/ericsson/security/log/Manual_rollback_Exec/%s"\
% FNAME,format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME
    SCRIPT_NAME = 'set_file_permission_rollback.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    log_file_presence()
    log_func(SCRIPT_NAME, 1, LOG_PATH)