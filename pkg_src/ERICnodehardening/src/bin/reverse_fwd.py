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
# Name      : reverse_fwd.py
# Purpose   :This script ensures that reverse path forwarding is
#               enforced with strict rpfilter.
#
# ********************************************************************
"""

import subprocess
import os
import time
import logging

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification

def reverse_fwd():
    """This function ensures that reverse path forwarding is enforced with strict rpfilter."""
    backup_files('/proc/sys/net/ipv4/conf/default/rp_filter', [])
    status = subprocess.check_output("cat /proc/sys/net/ipv4/conf/default/rp_filter", shell=True)
    mode = '1\n'

    if status == mode:
        print "\n**********Strict Reverse path forwarding for IPv4 \
communication is already enabled**********\n"
        logging.info('Strict Reverse path forwarding for IPv4 communication is already enabled')
    else:
        os.system("/sbin/sysctl -w net.ipv4.conf.default.rp_filter=1")
        print "\n**********Successfully enabled Strict Reverse path forwarding \
for IPv4 communication**********\n"
        logging.info('Successfully enabled Strict Reverse path forwarding for IPv4 communication')

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_reverse_fwd.log'
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
        reverse_fwd()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
