#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2021 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : disable_icmp_responses.py
# Purpose   : This script ensures bogus ICMP responses are ignored
# Reason    : EQEV-93417
# Authour   : XOOHRAN
# Revision  : A
# ********************************************************************
"""
import subprocess
import os
import time
import logging
import getpass
from sentinel_hardening import log_func
from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification
def icmp_responses():
    """This function disables icmp responses"""
    backup_files('/etc/sysctl.conf', [])
    os.system("/sbin/sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 > /dev/null 2>&1")
    os.system("/sbin/sysctl -w net.ipv4.route.flush=1 > /dev/null 2>&1")
    with open("/etc/sysctl.conf", 'r') as fin:
        data = fin.read()
    data = data.split('\n')
    try:
        if 'net.ipv4.icmp_ignore_bogus_error_responses = 1' in data:
            os.system("sed -i '/net.ipv4.icmp_ignore_bogus_error_responses = 1/d' /etc/sysctl.conf")
        if 'net.ipv4.icmp_ignore_bogus_error_responses=1' not in data:
            if 'net.ipv4.icmp_ignore_bogus_error_responses=0' in data:
                logging.warning('Customized value found!!')
            else:
                os.system("echo net.ipv4.icmp_ignore_bogus_error_responses=1 >> /etc/sysctl.conf")
                print "\n**********Successfully disabled bogus ICMP responses!**********\n"
                logging.info('Successfully disabled bogus ICMP responses!!!')
        elif 'net.ipv4.icmp_ignore_bogus_error_responses=1' in data:
            print "\n**********Ensured bogus ICMP responses are already disabled!**********\n"
            logging.warning('Ensured bogus ICMP responses are already disabled!!')
        else:
            logging.warning('Customized value found!!')
    except IOError:
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)
if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_disable_icmp_responses.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'disable_icmp_responses.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        icmp_responses()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
