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
# Name      : set_autologout_rollback.py
# Purpose   : This script resets autologout time to its default value.
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

def remove_autotimeout():
    """This Function sets the autotimeout to it's default state"""
    try:
        with open('/etc/profile', 'r') as in_file:
            file_name = in_file.read()
        file_name = file_name.strip('\n')
        if 'TMOUT' in file_name:
            if 'readonly TMOUT' in file_name:
                print"\nApplying rollback for autologout feature\n"
                logging.info('Applying rollback for auto log out feature\n')
                os.system("sed -i '/TMOUT/d' /etc/profile > /dev/null 2>&1")
                os.system("sed -i '/readonly/d' /etc/profile > /dev/null 2>&1")
                os.system("sed -i '/export/d' /etc/profile > /dev/null 2>&1")
                print"\nSuccessfully rolled back autologout feature\n"
                logging.info('Successfully rolled back autologout feature\n')
                adding_histcontrol()
        elif 'TMOUT' not in open(file_name).read():
            print"\nGranular Node Hardening not detected for autologout feature\n"
            logging.info('Granular Node Hardening not detected for autologout feature\n')
    except (IOError, subprocess.CalledProcessError):
        print"\nGranular Node Hardening not detected for autologout time feature\n"
        logging.info('Granular Node Hardening not detected for autologout time feature\n')

def adding_histcontrol():
    """This function adds the HISTCONTROL to the file"""
    data=subprocess.check_output("cat /etc/profile | grep ignorespace", \
shell=True, stderr=subprocess.PIPE).strip()
    specific_line = data
    new_line = "    export HISTCONTROL=ignoreboth"
    new_line2= "    export HISTCONTROL=ignoredups"
    with open("/etc/profile", "r") as f:
        lines = f.readlines()
    try:
        index = lines.index(specific_line + "\n")
    except ValueError:
        print("Specific line not found")
        exit()
    lines.insert(index + 1, new_line + "\n")
    lines.insert(index + 3, new_line2 + "\n")
    with open("/etc/profile", "w") as f:
        f.writelines(lines)
        f.close()

def checking_latestlog():
    """This function check the latest logs and compares"""
    try:
        granular_nh_logs_date_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep set_autologout  | sort -n | tail -1 \
| cut -d '/' -f 7 | cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        granular_nh_logs_time_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep set_autologout  | sort -n | tail -1 | cut -d '/' -f 7 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        rollback_logs_date_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        rollback_logs_time_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        if granular_nh_logs_date_stamp > rollback_logs_date_stamp:
            remove_autotimeout()
        elif granular_nh_logs_date_stamp < rollback_logs_date_stamp:
            print"\nGranular Node Hardening for the feature is not applied\n"
            logging.info('Granular Node Hardening for the feature is not applied\n')
        elif granular_nh_logs_date_stamp == rollback_logs_date_stamp and \
granular_nh_logs_time_stamp > rollback_logs_time_stamp:
            remove_autotimeout()
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
log/Apply_NH_Logs/Manual_Exec/ | grep set_autologout | sort -n \
| tail -1",shell=True, stderr=subprocess.PIPE).split()
            if not data:
                print"\nGranular Node Hardening log is not \
present for autologout \n"
                logging.info('Granular Node Hardening log is not \
present for autologout\n')
            else:
                print"\nGranular Node Hardening log are present for autologout\n"
                logging.info('Granular Node Hardening log is present for autologout\n')
                checking_latestlog()
        elif nh_check() == 1:
            print"\n******Full Node Hardening is applied on the \
server, rollback can not be applied******\n"
            logging.info('Full Node Hardening is applied on the server\n')
    except (IOError, subprocess.CalledProcessError):
        print"\nGranular Node Hardening not detected for autologout \n"
        logging.info('Granular Node Hardening not detected for autologout\n')

if __name__ == "__main__":
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_set_autologout_rollback.log'
    os.system("mkdir -p /ericsson/security/log/Manual_rollback_Exec/")
    FORMAT_STRING = '\n%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Manual_rollback_Exec/%s"\
                                                % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME
    SCRIPT_NAME = 'set_autologout_rollback.py'
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