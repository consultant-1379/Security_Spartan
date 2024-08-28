#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2019 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : disable_icmp_broadcast.py
# Purpose   :This script is used to disable ICMP package broadcast.
# ********************************************************************
"""

import os
import time
import logging
import subprocess

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification

def icmp_broadcast():
    """This function disables ICMP package broadcast."""

    backup_files('/etc/sysctl.conf', [])
    os.system("/sbin/sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 > /dev/null 2>&1")
    os.system("/sbin/sysctl -w net.ipv4.route.flush=1 > /dev/null 2>&1")
    with open("/etc/sysctl.conf", 'r') as fin:
        data = fin.read()
    data = data.split('\n')

    try:

        if 'net.ipv4.icmp_echo_ignore_broadcasts = 1' in data:
            os.system("sed -i '/net.ipv4.icmp_echo_ignore_broadcasts = 1/d' /etc/sysctl.conf")
        if 'net.ipv4.icmp_echo_ignore_broadcasts=1' not in data:
            if 'net.ipv4.icmp_echo_ignore_broadcasts=0' in data:
                logging.warning('Customized value found!!')
            else:
                os.system("echo net.ipv4.icmp_echo_ignore_broadcasts=1 >> /etc/sysctl.conf")
                print "\n**********Successfully disabled broadcast ICMP requests!**********\n"
                logging.info('Successfully disabled broadcast ICMP requests!!')
        elif 'net.ipv4.icmp_echo_ignore_broadcasts=1' in data:
            print "\n**********Broadcast ICMP requests are already disabled!**********\n"
        else:
            logging.warning('Customized value found!!')

    except IOError:
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)

if __name__ == "__main__":
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_disable_icmp_broadcast.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)

    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        icmp_broadcast()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
