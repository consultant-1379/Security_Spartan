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
# Name      : add_cipher_rollback.py
# Purpose   : This script resets Ciphers and MACS to its default value.
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

def remove_cipher():
    """This function removes the algorithms of cipher and MAC in \
both ssh and sshd config files"""
    try:
        ssh_file_path = '/etc/ssh/ssh_config'
        sshd_file_path = '/etc/ssh/sshd_config'
        with open(ssh_file_path, 'r') as file_ssh:
            data = file_ssh.read()
            file_ssh.close()
        data = data.strip('\n')
        if "Ciphers aes256-ctr,aes192-ctr,aes128-ctr,chacha20-poly1305@openssh.com,\
aes256-gcm@openssh.com,aes128-gcm@openssh.com" in data \
and "MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,\
hmac-sha2-256-etm@openssh.com" in data:
            print"\nApplying rollback for Cipher and MAC algorithms for client\n"
            logging.info('Applying rollback for Cipher and MAC algorithms for client\n')
            os.system("sed -i '/Ciphers aes256-ctr,aes192-ctr,aes128-ctr,\
chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com/d' /etc/ssh/ssh_config")
            os.system("sed -i '/MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,\
hmac-sha2-256-etm@openssh.com/d' /etc/ssh/ssh_config")
            print "\nRestarting the SSHD service. . . . . .\n"
            logging.info('Restarting the SSHD service\n')
            os.system("systemctl restart sshd")
            print"\n****Successfully rolled back Granular Node \
Hardening of Cipher and MAC algorithms for client****\n"
            logging.info('Successfully rolled back Granular Node \
Hardening of Cipher and MAC algorithms for client\n')
        else:
            print"\nGranular Node Hardening is not applied for \
Cipher and MAC for client\n"
            logging.info('Granular Node Hardening is not applied for \
Cipher and MAC for client\n')

        with open(sshd_file_path, 'r') as file_sshd:
            data = file_sshd.read()
            file_sshd.close()
        data = data.strip('\n')
        if "Ciphers aes256-ctr,aes192-ctr,aes128-ctr,chacha20-poly1305@openssh.com,\
aes256-gcm@openssh.com,aes128-gcm@openssh.com" in data \
and "MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,\
hmac-sha2-256-etm@openssh.com" in data:
            print"\nApplying rollback for Cipher and MAC algorithms for server\n"
            logging.info('Applying rollback for Cipher and MAC algorithms for server\n')
            os.system("sed -i '/Ciphers aes256-ctr,aes192-ctr,aes128-ctr,\
chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,\
aes128-gcm@openssh.com/d' /etc/ssh/sshd_config")
            os.system("sed -i '/MACs hmac-sha2-512,hmac-sha2-256,\
hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com/d' /etc/ssh/sshd_config")
            print"\n*****Successfully rolled back Granular Node \
Hardening of Cipher and MAC algorithms for server*****\n"
            logging.info('Successfully rolled back Granular Node \
Hardening of Cipher and MAC algorithms for server\n')
        else:
            print"\nGranular Node Hardening is not \
applied for Cipher and MAC for server\n"
            logging.info('Granular Node Hardening is not \
applied for Cipher and MAC for server\n')
    except (AttributeError, IOError):
        print"\n Error in Granular Node Hardening rollback \
for Cipher and MAC\n"
        logging.info('Error in Granular Node Hardening rollback \
for Cipher and MAC\n')

def checking_latestlog():
    """This function check the latest logs and compares"""
    try:
        granular_nh_logs_date_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep add_cipher  | sort -n | tail -1 \
| cut -d '/' -f 7 | cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        granular_nh_logs_time_stamp = subprocess.check_output("find /ericsson/security/\
log/Apply_NH_Logs/Manual_Exec/ | grep add_cipher  | sort -n | tail -1 | cut -d '/' -f 7 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        rollback_logs_date_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 1-8", shell=True, stderr=subprocess.PIPE)
        rollback_logs_time_stamp = subprocess.check_output("find /ericsson/NH_Rollback_logs/ \
| grep Restore | sort -n | tail -1 | cut -d '/' -f 4 \
| cut -c 10-15", shell=True, stderr=subprocess.PIPE)
        if granular_nh_logs_date_stamp > rollback_logs_date_stamp:
            remove_cipher()
        elif granular_nh_logs_date_stamp < rollback_logs_date_stamp:
            print"\nGranular Node Hardening for the feature is not applied\n"
            logging.info('Granular Node Hardening for the feature is not applied\n')
        elif granular_nh_logs_date_stamp == rollback_logs_date_stamp and \
granular_nh_logs_time_stamp > rollback_logs_time_stamp:
            remove_cipher()
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
log/Apply_NH_Logs/Manual_Exec/ | grep add_cipher | sort -n \
| tail -1",shell=True, stderr=subprocess.PIPE).split()
            if not data:
                print"\nGranular Node Hardening log is not \
present for Cipher and MAC\n"
                logging.info('Granular Node Hardening log is not \
present for Cipher and MAC\n')
            else:
                print"\nGranular Node Hardening log are present for cipher\n"
                logging.info('Granular Node Hardening log is present for cipher\n')
                checking_latestlog()
        elif nh_check() == 1:
            print"\n******Full Node Hardening is applied on the \
server, rollback can not be applied******\n"
            logging.info('Full Node Hardening is applied on the server\n')
    except (IOError, subprocess.CalledProcessError):
        print"\n Granular Node Hardening not detected for Cipher and MAC \n"
        logging.info('Granular Node Hardening not detected for Cipher and MAC\n')

if __name__ == "__main__":

    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_add_cipher_rollback.log'
    os.system("mkdir -p /ericsson/security/log/Manual_rollback_Exec/")
    FORMAT_STRING = '\n%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Manual_rollback_Exec/%s"\
						% FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Manual_rollback_Exec/%s" % FNAME
    SCRIPT_NAME = 'add_cipher_rollback.py'
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
