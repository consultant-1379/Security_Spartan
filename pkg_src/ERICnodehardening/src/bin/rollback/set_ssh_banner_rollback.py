#!/usr/bin/python
# -*- coding: utf-8 -*-
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
# Name      : set_ssh_banner_rollback.py
# Purpose   : This script resets ssh_banner to its default state
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

def ssh_banner():
    """This function rollback the ssh_banner script """
    try:
        file_name = subprocess.check_output("cat /etc/issue", \
shell=True, stderr=subprocess.PIPE)
        filename = subprocess.check_output("cat /etc/issue.net", \
shell=True, stderr=subprocess.PIPE)
        parameters = ['\S',R'Kernel \r on an \m']
        if all(word in file_name for word in parameters) \
and all(word in filename for word in parameters):
            print"\nGranular Node Hardening is not applied \
for SSH login banner\n"
            logging.info('Granular Node Hardening is not applied \
for SSH login banner\n')
        else:
            print"\nApplying rollback for ssh banner. . . . . \n"
            logging.info('Applying rollback for ssh banner\n')
            os.system("cp /ericsson/security/BACKUP_CONFIG_FILES/0etc0issue /etc/issue")
            os.system("cp /ericsson/security/BACKUP_CONFIG_FILES/0etc0issue.net /etc/issue.net")
 #          with open('/etc/issue', 'w') as file, open('/etc/issue.net', 'w') as file_1:
 #              for items in parameters:
 #                  file.write('%s\n' %items)
#                   file_1.write('%s\n' %items)
            print "\n****Successfully rolled back Granular Node Hardening \
for SSH login banner****\n"
            logging.info('Successfully rolled back Granular Node Hardening \
for SSH login banner\n')
        ssh_file_replace()
    except (subprocess.CalledProcessError, IOError):
        print"\nError in Granular Node Hardening rollback for \
SSH login banner\n"
        logging.info('Error in Granular Node Hardening rollback for \
SSH login banner\n')

def ssh_file_replace():
    """This function replace the banner message in sshd file"""
    try:
        data=subprocess.check_output("cat /etc/ssh/sshd_config | grep Banner", \
shell=True, stderr=subprocess.PIPE)
        if "Banner /etc/issue.net" in data:
            with open('/etc/ssh/sshd_config', 'r') as file:
                newtext = file.read().replace('Banner /etc/issue.net', '#Banner none')
            with open('/etc/ssh/sshd_config', 'w') as file:
                file.write(newtext)
                file.close()
            print "\nRestarting the SSHD service. . . . . .\n"
            logging.info('Restarting the SSHD service')
            os.system("systemctl restart sshd")
    except (subprocess.CalledProcessError, IOError):
        print"\nGranular Node Hardening not detected for ssh banner\n"
        logging.info('Granular Node Hardening not detected for ssh banner\n')

def checking_latestlog():
    """This function check the latest logs and compares"""
    try:
        granular_nh_logs_date_stamp = subprocess.check_output("find /ericsson/security/log/\
Apply_NH_Logs/Manual_Exec/ | grep set_ssh_banner  | sort -n | tail -1 \
| cut -d '/' -f 7 | cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        granular_nh_logs_time_stamp = subprocess.check_output("find /ericsson/security/log/\
Apply_NH_Logs/Manual_Exec/ | grep set_ssh_banner  | sort -n | tail -1 \
| cut -d '/' -f 7 | cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        rollback_logs_date_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        rollback_logs_time_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        if granular_nh_logs_date_stamp > rollback_logs_date_stamp:
            ssh_banner()
        elif granular_nh_logs_date_stamp < rollback_logs_date_stamp:
            print"\n Granular Node Hardening for the feature is not applied \n"
            logging.info('Granular Node Hardening for the feature is not applied\n')
        elif granular_nh_logs_date_stamp == rollback_logs_date_stamp and \
		granular_nh_logs_time_stamp > rollback_logs_time_stamp:
            ssh_banner()
        elif granular_nh_logs_time_stamp < rollback_logs_time_stamp:
            print"\nGranular Node Hardening is not applied for the feature\n"
            logging.info('Granular Node Hardening is not applied for the feature\n')
        else:
            print"\nGranular Node Hardening is not applied \n"
            logging.info('Granular Node Hardening is not applied \n')
    except (subprocess.CalledProcessError, IOError):
        print"\nGranular Node Hardening is not detected for ssh banner\n"
        logging.info('Granular Node Hardening is not detected for ssh banner\n')

def log_file_presence():
    """This function check whether granular log for particular feature present or not"""
    try:
        if nh_check() == 0:
            data = subprocess.check_output("find /ericsson/security/log/\
Apply_NH_Logs/Manual_Exec/ | grep set_ssh_banner | sort -n \
| tail -1",shell=True, stderr=subprocess.PIPE).split()
            if not data:
                print"\n Granular Node Hardening log is not present for ssh banner \n"
                logging.info('Granular Node Hardening log is not present for ssh banner\n')
            else:
                print"\nGranular Node Hardening log is present for ssh banner\n"
                logging.info('Granular Node Hardening log is present for ssh banner\n')
                checking_latestlog()
        elif nh_check() == 1:
            print"\n***Full node hardening is applied on the \
server, rollback cannot be apllied***\n"
            logging.info('Full Node Hardening is applied on the server')
    except (subprocess.CalledProcessError, IOError):
        print"\nGranular Node Hardening not detected\n"
        logging.info('Granular Node Hardening not detected\n')

if __name__ == "__main__":

    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_set_ssh_banner_rollback.log'
    os.system("mkdir -p /ericsson/security/log/Manual_rollback_Exec/")
    FORMAT_STRING = '\n%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME
    SCRIPT_NAME = 'set_ssh_banner_rollback.py'
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
