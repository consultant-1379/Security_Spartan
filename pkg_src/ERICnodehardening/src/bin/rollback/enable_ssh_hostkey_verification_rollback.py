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
# Name      : enable_ssh_hostkey_verification_rollback.py
# Purpose   : This script sets hostkey verification to its default state
# Author    : ZKATSHR
# Reason    : EQEV-101907
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

def set_hostkeyverification():
    """This function rollback the enable_hostkey_verification"""
    try:
        data1 = subprocess.check_output("cat /etc/ssh/ssh_config | grep Verifyhostkeydns", \
shell=True, stderr=subprocess.PIPE).strip()
        data2 = subprocess.check_output("cat /etc/ssh/ssh_config | \
grep stricthostkeychecking", shell=True, stderr=subprocess.PIPE).strip()
        if data1 == "Verifyhostkeydns ask" and data2 == "stricthostkeychecking ask":
            print"\nApplying rollback for hostkey verifiacation. . . . . .\n"
            logging.info('Applying rollback for hostkey verifiacation\n')
            os.system("sed -i '/Verifyhostkeydns/d' /etc/ssh/ssh_config")
            os.system("sed -i '/stricthostkeychecking/d' /etc/ssh/ssh_config")
            print "\nRestarting the SSHD service. . . . . .\n"
            logging.info('Restarting the SSHD service')
            os.system("systemctl restart sshd")
            print"\n****Successfully rolled back Granular Node Hardening of \
ssh hostkey and dns verification****\n"
            logging.info('Successfully rolled back Granular Node Hardening of \
ssh hostkey and dns verification')
    except subprocess.CalledProcessError:
        print"\nGranular Node Hardening is not applied for \
ssh hostkey and dns verification\n"
        logging.info('Granular Node Hardening is not applied for \
ssh hostkey and dns verification\n')

def checking_latestlog():
    """This function check the latest logs and compares"""
    try:
        granular_nh_logs_date_stamp = subprocess.check_output("find /ericsson/security\
/log/Apply_NH_Logs/Manual_Exec/ | grep set_ssh_hostKey  | sort -n | tail -1 \
| cut -d '/' -f 7 | cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        granular_nh_logs_time_stamp = subprocess.check_output("find /ericsson/security\
/log/Apply_NH_Logs/Manual_Exec/ | grep set_ssh_hostKey  | sort -n | tail -1 \
| cut -d '/' -f 7 | cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        rollback_logs_date_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 | cut -c 1-8", shell=True, \
stderr=subprocess.PIPE)
        rollback_logs_time_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 | cut -c 10-15", shell=True, \
stderr=subprocess.PIPE)
        if granular_nh_logs_date_stamp > rollback_logs_date_stamp:
            set_hostkeyverification()
        elif granular_nh_logs_date_stamp < rollback_logs_date_stamp:
            print"\nGranular Node hardening is not applied for the feature\n"
            logging.info('Granular Node hardening is not applied for the feature\n')
        elif granular_nh_logs_date_stamp == rollback_logs_date_stamp and \
granular_nh_logs_time_stamp > rollback_logs_time_stamp:
            set_hostkeyverification()
        elif granular_nh_logs_time_stamp < rollback_logs_time_stamp:
            print"\nGranular Node hardening for the feature is not applied\n"
            logging.info('Granular Node hardening for the feature is not applied\n')
        else:
            print"\nGranular Node hardening is not applied\n"
            logging.info('Granular Node hardening is not applied\n')
    except (subprocess.CalledProcessError, IOError):
        print"\nGranular Node Hardening is not detected for hostkey verification\n"
        logging.info('Granular Node Hardening is not detected for hostkey verification\n')

def log_file_presence():
    """This function check whether granular log for particular feature present or not"""
    try:
        if nh_check() == 0:
            data = subprocess.check_output("find /ericsson/security/log/Apply_NH_Logs/Manual_Exec/ \
| grep set_ssh_hostKey | sort -n | tail -1",shell=True, \
stderr=subprocess.PIPE).split()
            if not data:
                print"\nGranular Node Hardening log is not present for \
hostkeyverification feature\n"
                logging.info('Granular Node Hardening log is not present for \
hostkeyverification feature\n')
            else:
                print"\nGranular Node Hardening log is present for \
hostkeyverification feature\n"
                logging.info('Granular Node Hardening log is present for \
hostkeyverification feature\n')
                checking_latestlog()
        elif nh_check() == 1:
            print"\n***Full Node Hardening is applied on the \
server, rollback cannot be applied***\n"
            logging.info('Full Node Hardening is applied on the server\n')
    except (subprocess.CalledProcessError, IOError):
        print"\nGranular Node Hardening not detected \n"
        logging.info('Granular Node Hardening not detected \n')

if __name__ == "__main__":

    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_enable_ssh_hostkey_verification_rollback.log'
    os.system("mkdir -p /ericsson/security/log/Manual_rollback_Exec/")
    FORMAT_STRING = '\n%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME
    SCRIPT_NAME = 'enable_ssh_hostkey_verification_rollback.py'
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