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
# Name      : ensure_date_time_info.py
# Purpose   : This script ensures that modify date and time information
#             are collected.
# Author    : ZATLPOE
# Reason    : EQEV-88535
# Revision  : A
# ********************************************************************
"""
import subprocess
import os
import time
import logging
import getpass

from Verify_NH_Config import configure_nh
from sentinel_hardening import log_func
from user_verification import user_verification

def customized_date_time_info():
    if not os.path.exists('/etc/audit/rules.d/50-time_change.rules'):
        ensure_date_time_info()
    else:
        with open("/etc/audit/rules.d/50-time_change.rules", 'r') as fin:
            data = fin.read()
        cus_rules = ['#-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change', \
'#-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change', \
'#-a always,exit -F arch=b64 -S clock_settime -k time-change', \
'#-w /etc/localtime -p wa -k time-change']
        if any(rule in data for rule in cus_rules):
            print("\nThe rules for modification of date and time information are collected feature \
are already disabled by customization!\n")
            logging.info('\nThe rules for modification of date and time information are collected \
feature are already disabled by customization!\n')
        else:
            ensure_date_time_info()

def ensure_date_time_info():
    """This function ensure that modify date and time information are collected."""

    try:
        if os.path.exists("/etc/audit/rules.d/50-time_change.rules") is True:
            logging.info('The directory is already present\n')
        else:
            os.system("touch /etc/audit/rules.d/50-time_change.rules")
            logging.info('Successfully created the new directory\n')

        with open("/etc/audit/rules.d/50-time_change.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        cmd = "getconf LONG_BIT"
        result = subprocess.check_output(cmd, shell=True)

        if int(result) == 64:
            if '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change' not in data\
 and '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change' not in data \
and '-a always,exit -F arch=b64 -S clock_settime -k time-change' not in data and \
'-a always,exit -F arch=b32 -S clock_settime -k time-change' not in data and \
'-w /etc/localtime -p wa -k time-change' not in data:
                os.system("echo -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k \
time-change >> /etc/audit/rules.d/50-time_change.rules")
                os.system("echo -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S \
stime -k time-change >> /etc/audit/rules.d/50-time_change.rules")
                os.system("echo -a always,exit -F arch=b64 -S clock_settime -k time-change \
>> /etc/audit/rules.d/50-time_change.rules")
                os.system("echo -a always,exit -F arch=b32 -S clock_settime -k time-change \
>> /etc/audit/rules.d/50-time_change.rules")
                os.system("echo -w /etc/localtime -p wa -k time-change \
>> /etc/audit/rules.d/50-time_change.rules")
                print "\n**********Successfully ensured that modify date and time are \
collected!**********\n"
                logging.info('Successfully ensured that modify date and time are collected!\n')
            elif '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change' in data \
and '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change' in data and \
'-a always,exit -F arch=b64 -S clock_settime -k time-change' in data and \
'-a always,exit -F arch=b32 -S clock_settime -k time-change' in data and \
'-w /etc/localtime -p wa -k time-change' in data:
                print "Modified date and time events are already collected\n"
                logging.info('Modified date and time events are already collected\n')
            else:
                logging.warning('Customized rule is found!!\n')
        elif int(result) == 32:
            if '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change' \
not in data and '-a always,exit -F arch=b32 -S clock_settime -k time-change' not in data and \
'-w /etc/localtime -p wa -k time-change' not in data:
                os.system("echo -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime \
-k time-change >> /etc/audit/rules.d/50-time_change.rules")
                os.system("echo -a always,exit -F arch=b32 -S clock_settime -k time-change \
>> /etc/audit/rules.d/50-time_change.rules")
                os.system("echo -w /etc/localtime -p wa -k time-change \
>> /etc/audit/rules.d/50-time_change.rules")
                print "\n**********Successfully ensured that modify date and time \
are collected!**********\n"
                logging.info('Successfully ensured that modify date and time are collected!')
            elif '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change' \
in data and '-a always,exit -F arch=b32 -S clock_settime -k time-change' in data and \
'-w /etc/localtime -p wa -k time-change' in data:
                print "Modified date and time events are already collected\n"
                logging.info('Modified date and time events are already collected\n')
            else:
                logging.warning('Customized rule is found!!\n')

        os.system("service auditd restart > /dev/null 2>&1")
        logging.info('Restarting the auditd service!!')
    except IOError:
        logging.error('Script exited abnormally')

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_ensure_date_time_info.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'ensure_date_time_info.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        customized_date_time_info()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
