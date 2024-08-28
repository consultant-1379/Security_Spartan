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
# Name      : enforce_ssh_timeout_rollback.py
# Purpose   : This script reset ssh_timeout to its default value
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

def enforce_ssh_timeout():
    """This function rollback enable_ssh_timeout"""
    try:
        file_name = "/etc/ssh/sshd_config"
        with open(file_name, 'r') as file:
            data = file.read()
        data = data.strip('\n')
        data1=subprocess.check_output("cat /etc/ssh/sshd_config \
| grep ClientAliveInterval", shell=True, stderr=subprocess.PIPE)
        data2=subprocess.check_output("cat /etc/ssh/sshd_config \
| grep ClientAliveCountMax", shell=True, stderr=subprocess.PIPE)
        if "ClientAliveInterval 900" in data1 and "ClientAliveCountMax 0" in data2:
            print"\nApplying rollback for ssh timeout. . . . . .\n"
            logging.info('Applying rollback for ssh timeout\n')
            with open(file_name, 'r') as file:
                newtext = file.read().replace('ClientAliveInterval 900', '#ClientAliveInterval 0')
            with open(file_name, 'w') as file1:
                file1.write(newtext)
                file1.close()
            with open(file_name, 'r') as file2:
                new_text = file2.read().replace('ClientAliveCountMax 0', '#ClientAliveCountMax 3')
            with open(file_name, 'w') as file3:
                file3.write(new_text)
                file3.close()
            print "\nRestarting the SSHD service. . . . . .\n"
            logging.info('Restarting the SSHD service')
            os.system("systemctl restart sshd")
            print "\n****Successfully rolled back Granular Node \
Hardening for SSH Time out value****\n"
            logging.info('Successfully rolled back Granular Node \
Hardening for SSH Time out value\n')
        elif "#ClientAliveInterval 0" in data1 and "#ClientAliveCountMax 3" in data2:
            print"\nGranular Node Hardening is not applied for \
SSH Time out value\n"
            logging.info('Granular Node Hardening is not applied for \
SSH Time out value\n')
    except (subprocess.CalledProcessError, IOError):
        print"\nError in Granular Node Hardening rollback for \
SSH Time out value\n"
        logging.info('Error in Granular Node Hardening rollback for \
SSH Time out value\n')

def checking_latestlog():
    """This function check the latest logs and compares"""
    try:
        granular_nh_logs_date_stamp = subprocess.check_output("find /ericsson/security/log\
/Apply_NH_Logs/Manual_Exec/ | grep enforce_ssh_timeout  | sort -n | tail -1 | cut -d '/' -f 7 \
| cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        granular_nh_logs_time_stamp = subprocess.check_output("find /ericsson/security/log\
/Apply_NH_Logs/Manual_Exec/ | grep enforce_ssh_timeout  | sort -n | tail -1 | cut -d '/' -f 7 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        rollback_logs_date_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/\
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 | cut -c 1-8", \
shell=True, stderr=subprocess.PIPE)
        rollback_logs_time_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/\
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 | cut -c 10-15", \
shell=True, stderr=subprocess.PIPE)
        if granular_nh_logs_date_stamp > rollback_logs_date_stamp:
            enforce_ssh_timeout()
        elif granular_nh_logs_date_stamp < rollback_logs_date_stamp:
            print"\n Granular Node Hardening for the feature is not applied \n"
            logging.info('Granular Node Hardening for the feature is not applied\n')
        elif granular_nh_logs_date_stamp == rollback_logs_date_stamp and \
granular_nh_logs_time_stamp > rollback_logs_time_stamp:
            enforce_ssh_timeout()
        elif granular_nh_logs_time_stamp < rollback_logs_time_stamp:
            print"\nGranular Node Hardening is not applied for the feature \n"
            logging.info('Granular Node Hardening is not applied for the feature \n')
        else:
            print"\nGranular Node Hardening is not applied \n"
            logging.info('Granular Node Hardening is not applied\n')
    except (subprocess.CalledProcessError, IOError):
        print"\nGranular Node Hardening is not detected for ssh timeout\n"
        logging.info('Granular Node Hardening is not detected for ssh timeout\n')

def log_file_presence():
    """This function check whether granular log for particular feature present or not"""
    try:
        if nh_check() == 0:
            data = subprocess.check_output("find /ericsson/security/log/Apply_NH_Logs/Manual_Exec/ \
| grep enforce_ssh_timeout | sort -n | tail -1",shell=True, stderr=subprocess.PIPE).split()
            if not data:
                print"\n Granular Node Hardening log is not present for ssh timeout \n"
                logging.info('Granular Node Hardening log is not present for ssh timeout\n')
            else:
                print"\nGranular Node Hardening log is present for ssh timeout\n"
                logging.info('Granular Node Hardening log is present for ssh timeout\n')
                checking_latestlog()
        elif nh_check() == 1:
            print"\n***Full node hardening is applied on the \
server, rollback cannot be applied***\n"
            logging.info('Full Node Hardening is applied on the server\n')
    except (subprocess.CalledProcessError, IOError):
        print"\nGranular Node Hardening not detected \n"
        logging.info('Granular Node Hardening not detected \n')

if __name__ == "__main__":

    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_enforce_ssh_timeout_rollback.log'
    os.system("mkdir -p /ericsson/security/log/Manual_rollback_Exec/")
    FORMAT_STRING = '\n%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME
    SCRIPT_NAME = 'enforce_ssh_timeout_rollback.py'
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