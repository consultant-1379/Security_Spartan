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
# Name      : enable_ssh_proto_v2_rollback.py
# Purpose   : This script restes ssh_proto_v2 to its default value
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

def enable_ssh_proto_v2():
    """This function remove protocol 2  """
    try:
        file_name = "/etc/ssh/ssh_config"
        data=subprocess.check_output("cat /etc/ssh/ssh_config \
| grep Protocol", shell=True, stderr=subprocess.PIPE).strip()
        if data == "Protocol 2":
            print"\nApplying rollback for ssh V2. . . . .\n"
            logging.info('Applying rollback for ssh V2\n')
            with open(file_name) as fin:
                newconfig = fin.read().replace('Protocol 2', '#   Protocol 2')
            with open(file_name, 'w') as fout:
                fout.write(newconfig)
                fout.close()
            print "\nRestarting the SSHD service. . . . . .\n"
            logging.info('Restarting the SSHD service')
            os.system("systemctl restart sshd")
            print "\n****Successfully rolled back Granular Node \
Hardening for Protocol v2****\n"
            logging.info('Successfully rolled back Granular Node \
Hardening for Protocol v2\n')
        elif data == "#   Protocol 2":
            print"\nGranular Node Hardening is not applied \
for Protocol v2\n"
            logging.info('Granular Node Hardening is not applied \
for Protocol v2\n')
    except subprocess.CalledProcessError:
        print"\nError in Granular Node Hardening rollback for \
Protocol v2\n"
        logging.info('Error in Granular Node Hardening rollback for \
Protocol v2\n')


def checking_latestlog():
    """This function check the latest logs and compares"""
    try:
        granular_nh_logs_date_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep enable_ssh_proto_v2  | sort -n | tail -1 \
| cut -d '/' -f 7 | cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        granular_nh_logs_time_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep enable_ssh_proto_v2  | sort -n | tail -1 \
| cut -d '/' -f 7 | cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        rollback_logs_date_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 1-8", shell=True,stderr=subprocess.PIPE)
        rollback_logs_time_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 10-15", shell=True,stderr=subprocess.PIPE)
        if granular_nh_logs_date_stamp > rollback_logs_date_stamp:
            enable_ssh_proto_v2()
        elif granular_nh_logs_date_stamp < rollback_logs_date_stamp:
            print"\nGranular Node Hardening not applied for the feature\n"
            logging.info('Granular Node Hardening not applied for the feature\n')
        elif granular_nh_logs_date_stamp == rollback_logs_date_stamp and \
granular_nh_logs_time_stamp > rollback_logs_time_stamp:
            enable_ssh_proto_v2()
        elif granular_nh_logs_time_stamp < rollback_logs_time_stamp:
            print"\nGranular Node Hardening is not applied for the feature \n"
            logging.info('Granular Node Hardening is not applied for the feature\n')
        else:
            print"\nGranular Node Hardening is not applied\n"
            logging.info('Granular Node Hardening is not applied\n')
    except (subprocess.CalledProcessError, IOError):
        print"\nGranular Node Hardening is not detected for ssh V2\n"
        logging.info('Granular Node Hardening is not detected for ssh V2\n')

def log_file_presence():
    """This function check whether granular log for particular feature present or not"""
    try:
        if nh_check() == 0:
            data = subprocess.check_output("find /ericsson/security/log/Apply_NH_Logs/Manual_Exec/ \
| grep enable_ssh_proto_v2 | sort -n | tail -1",shell=True, stderr=subprocess.PIPE).split()
            if not data:
                print"\nGranular Node Hardeninglog is not present for ssh V2\n"
            else:
                print"\nGranular Node Hardening log is present for ssh V2\n"
                checking_latestlog()
        elif nh_check() == 1:
            print"\n***Full Node Hardening is applied on the \
server, rollback cannot be applied***\n"
            logging.info('Full Node Hardening is applied on the server')
    except (subprocess.CalledProcessError, IOError):
        print"\nGranular Node Hardening not detected \n"
        logging.info('Granular Node Hardening not detected \n')

if __name__ == "__main__":

    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_enable_ssh_proto_v2_rollback.log'
    os.system("mkdir -p /ericsson/security/log/Manual_rollback_Exec/")
    FORMAT_STRING = '\n%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME
    SCRIPT_NAME = 'enable_ssh_proto_v2_rollback.py'
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