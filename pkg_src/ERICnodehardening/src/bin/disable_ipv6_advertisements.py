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
# Name      : disable_ipv6_advertisements.py
# Purpose   : This script is to ensure that Ipv6 router advertisements
#             are not accepted.
# Author    : ZBARPHU
# Reason    : EQEV-93878
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
def disable_ipv6_adv():
    """This function is to ensure that Ipv6 router advertisements are not accepted"""
    backup_files('/etc/sysctl.conf', [])
    os.system("/sbin/sysctl -w net.ipv6.conf.all.accept_ra=0 > /dev/null 2>&1")
    os.system("/sbin/sysctl -w net.ipv6.conf.default.accept_ra=0 > /dev/null 2>&1")
    os.system("/sbin/sysctl -w net.ipv6.route.flush=1 > /dev/null 2>&1")
    with open("/etc/sysctl.conf", 'r') as fin:
        data = fin.read()
    data = data.split('\n')
    try:
        if 'net.ipv6.conf.all.accept_ra = 0' in data or \
'net.ipv6.conf.default.accept_ra = 0' in data:
            os.system("sed -i '/net.ipv6.conf.all.accept_ra = 0/d' /etc/sysctl.conf")
            os.system("sed -i '/net.ipv6.conf.default.accept_ra = 0/d' /etc/sysctl.conf")
        if 'net.ipv6.conf.all.accept_ra=0' not in data and \
'net.ipv6.conf.default.accept_ra=0' not in data:
            if 'net.ipv6.conf.all.accept_ra=1' in data or \
'net.ipv6.conf.default.accept_ra=1' in data:
                logging.warning('Customized value found!!')
            else:
                os.system("echo net.ipv6.conf.all.accept_ra=0 >> /etc/sysctl.conf")
                os.system("echo net.ipv6.conf.default.accept_ra=0 >> /etc/sysctl.conf")
                print "\n**********Successfully ensured Ipv6 router advertisements are \
not accepted!**********\n"
                logging.info('Successfully ensured Ipv6 router advertisements are not accepted!!')
        elif 'net.ipv6.conf.all.accept_ra=0' in data and \
'net.ipv6.conf.default.accept_ra=0' in data:
            print "\n**********Accepting Ipv6 router advertisements are already \
disabled!**********\n"
            logging.warning('Accepting Ipv6 router advertisements are already disabled!!')
        else:
            logging.warning('Customized value found!!')

    except IOError:
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)
if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_disable_ipv6_advertisements.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'disable_ipv6_advertisements.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        disable_ipv6_adv()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
