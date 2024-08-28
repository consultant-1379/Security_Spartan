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
# Name      : capture_performance.py
# Purpose   : This script captures the performance logs and saves it
#             under the directory:
#             /ericsson/security/log/performance_logs/perfo rmance_logs_<date>
# ********************************************************************
"""

import os
import subprocess
import time
import logging

from Verify_NH_Config import configure_nh
from user_verification import user_verification

timestr = time.strftime("%Y%m%d-%H%M%S")

def performance():
    """This script captures the performance logs and saves it under:
       /ericsson/security/log/performance_logs/ path"""
    dir_name = '_performance_logs_' + timestr
    os.system("mkdir -p /ericsson/security/log/performance_logs/%s" % dir_name)

    print "\n*********Capturing the performance logs . . .\n"
    logging.info('Capturing the performance logs')
    os.system('top -n 2 > /ericsson/security/log/performance_logs/%s/top.txt' % dir_name)
    os.system('ps -ef > /ericsson/security/log/performance_logs/%s/ps.txt' % dir_name)
    os.system('sar 2 5 > /ericsson/security/log/performance_logs/%s/sar.txt' % dir_name)
    os.system('iostat > /ericsson/security/log/performance_logs/%s/iostat.txt' % dir_name)
    os.system('vmstat > /ericsson/security/log/performance_logs/%s/vmstat.txt' % dir_name)
    os.system('mpstat > /ericsson/security/log/performance_logs/%s/mpstat.txt' % dir_name)
    os.system('netstat > /ericsson/security/log/performance_logs/%s/netstat.txt' % dir_name)
    logging.info('The logs are saved at : /ericsson/security/log/performance_logs directory')
    print "\n**********The logs are saved at : \
/ericsson/security/log/performance_logs/%s" % dir_name, "**********\n"

if __name__ == '__main__':
    user_verification()
    fname = timestr + '_capture_performance.log'
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
        performance()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
