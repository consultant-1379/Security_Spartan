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
# Name      : ensure_system_network.py
# Purpose   : This script ensures that the system network environment
#             are collected.
# Author    : ZATLPOE
# Reason    : EQEV-94613
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

def customized_system_network():
    if not os.path.exists('/etc/audit/rules.d/50-system_local.rules'):
        ensure_system_network()
    else:
        with open("/etc/audit/rules.d/50-system_local.rules", 'r') as fin:
            data = fin.read()
        cus_rules = ['#-a always,exit -F arch=b64 -S sethostname -S setdomainname -k \
system-locale', '#-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale', \
'#-w /etc/issue -p wa -k system-locale', '#-w /etc/issue.net -p wa -k system-locale', \
'#-w /etc/hosts -p wa -k system-locale', '#-w /etc/sysconfig/network -p wa -k system-locale']

        if any(rule in data for rule in cus_rules):
            print("\nThe rules for ensure that system's network environment are collected feature \
are already disabled by customization!\n")
            logging.info('\nThe rules for ensure that systems network environment are collected \
feature are already disabled by customization!\n')
        else:
            ensure_system_network()

def ensure_system_network():
    """This function ensure that system's network environment are collected."""

    try:
        if os.path.exists("/etc/audit/rules.d/50-system_local.rules") is True:
            logging.info('The directory is already present\n')
        else:
            os.system("touch /etc/audit/rules.d/50-system_local.rules")
            logging.info('Successfully created the new directory\n')

        with open("/etc/audit/rules.d/50-system_local.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        cmd = "getconf LONG_BIT"
        result = subprocess.check_output(cmd, shell=True)

        if int(result) == 64:
            if '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale' in \
data and '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale' in data \
and '-w /etc/issue -p wa -k system-locale' in data and '-w /etc/issue.net -p wa -k system-locale' \
in data and '-w /etc/hosts -p wa -k system-locale' in data and \
'-w /etc/sysconfig/network -p wa -k system-locale' in data:
                print "Systems network environment are already collected\n"
                logging.info('Systems network environment are already collected\n')
            elif '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale' not \
in data and '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale' not in \
data and '-w /etc/issue -p wa -k system-locale' not in data and \
'-w /etc/issue.net -p wa -k system-locale' not in data and \
'-w /etc/hosts -p wa -k system-locale' not in data and \
'-w /etc/sysconfig/network -p wa -k system-locale' not in data:
                os.system("echo -a always,exit -F arch=b64 -S sethostname -S setdomainname -k \
system-locale >> /etc/audit/rules.d/50-system_local.rules")
                os.system("echo -a always,exit -F arch=b32 -S sethostname -S setdomainname -k \
system-locale >> /etc/audit/rules.d/50-system_local.rules")
                os.system("echo -w /etc/issue -p wa -k system-locale \
>> /etc/audit/rules.d/50-system_local.rules")
                os.system("echo -w /etc/issue.net -p wa -k system-locale \
>> /etc/audit/rules.d/50-system_local.rules")
                os.system("echo -w /etc/hosts -p wa -k system-locale \
>> /etc/audit/rules.d/50-system_local.rules")
                os.system("echo -w /etc/sysconfig/network -p wa -k system-locale \
>> /etc/audit/rules.d/50-system_local.rules")
                print "\n**********Successfully ensured systems network environment \
are collected!**********\n"
                logging.info('Successfully ensured systems network environment are collected!')
            else:
                logging.warning('Customized rule is found!!\n')
        elif int(result) == 32:
            if '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale' in \
data and '-w /etc/issue -p wa -k system-locale' in data and \
'-w /etc/issue.net -p wa -k system-locale' in data and '-w /etc/hosts -p wa -k system-locale' in \
data and '-w /etc/sysconfig/network -p wa -k system-locale' in data:
                print "Systems network environment are already collected\n"
                logging.info('Systems network environment are already collected\n')
            elif '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale' not \
in data and '-w /etc/issue -p wa -k system-locale' not in data and \
'-w /etc/issue.net -p wa -k system-locale' not in data and '-w /etc/hosts -p wa -k system-locale' \
not in data and '-w /etc/sysconfig/network -p wa -k system-locale' not in data:
                os.system("echo -a always,exit -F arch=b32 -S sethostname -S setdomainname -k \
system-locale >> /etc/audit/rules.d/50-system_local.rules")
                os.system("echo -w /etc/issue -p wa -k system-locale \
>> /etc/audit/rules.d/50-system_local.rules")
                os.system("echo -w /etc/issue.net -p wa -k system-locale \
>> /etc/audit/rules.d/50-system_local.rules")
                os.system("echo -w /etc/hosts -p wa -k system-locale \
>> /etc/audit/rules.d/50-system_local.rules")
                os.system("echo -w /etc/sysconfig/network -p wa -k system-locale \
>> /etc/audit/rules.d/50-system_local.rules")
                print "\n**********Successfully ensured systems network environment are \
collected!**********\n"
                logging.info('Successfully ensured systems network environment are collected!')
            else:
                logging.warning('Customized rule is found!!\n')

        os.system("service auditd restart > /dev/null 2>&1")
        logging.info('Restarting the auditd service!!')

    except IOError:
        logging.error('Script exited abnormally')

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_ensure_system_network.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'ensure_system_network.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        customized_system_network()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
