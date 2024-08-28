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
# Name      : enable_tcp_syncookies.py
# Purpose   : This script enables tcp syn cookies.
# Author    : ZATLPOE
# Reason    : EQEV-93877
# Revision  : A
# ********************************************************************
"""
import subprocess
import os
import time
import logging
import getpass
from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from sentinel_hardening import log_func
from user_verification import user_verification
def enable_tcp_syncookies():
    """This function enables tcp syn cookies"""
    backup_files('/etc/sysctl.conf', [])
    os.system("/sbin/sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null 2>&1")
    os.system("/sbin/sysctl -w net.ipv4.route.flush=1 > /dev/null 2>&1")
    with open("/etc/sysctl.conf", 'r') as fin:
        data = fin.read()
    data = data.split('\n')
    try:
        if 'net.ipv4.tcp_syncookies = 1' in data:
            os.system("sed -i '/net.ipv4.tcp_syncookies = 1/d' /etc/sysctl.conf")
        if 'net.ipv4.tcp_syncookies=1' not in data:
            if 'net.ipv4.tcp_syncookies=0' in data:
                logging.warning('Customized value found!!')
            else:
                os.system("echo net.ipv4.tcp_syncookies=1 >> /etc/sysctl.conf")
                print "\n**********Successfully enabled TCP SYN Cookies!!**********\n"
                logging.info('Successfully enabled TCP SYN Cookies!!')
        elif 'net.ipv4.tcp_syncookies=1' in data:
            print "\n**********TCP SYN Cookies is already enabled!**********\n"
            logging.warning('TCP SYN Cookies is already enabled')
        else:
            logging.warning('Customized value found!!')
    except IOError:
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_enable_tcp_syncookies.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'enable_tcp_syncookies.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        enable_tcp_syncookies()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
