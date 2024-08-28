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
# Name      : ensure_system_access.py
# Purpose   : This script ensures that the system mandatory access
#             controls are collected.
# Author    : ZATLPOE
# Reason    : EQEV-94614
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

def customized_system_access():
    if not os.path.exists('/etc/audit/rules.d/50-MAC_policy.rules'):
        ensure_system_access()
    else:
        with open("/etc/audit/rules.d/50-MAC_policy.rules", 'r') as fin:
            data = fin.read()
        cus_rules = ['#-w /etc/selinux/ -p wa -k MAC-policy', \
'#-w /usr/share/selinux/ -p wa -k MAC-policy']
        if any(rule in data for rule in cus_rules):
            print("\nThe rules for ensure that system's Mandatory Access Controls are \
collected feature are already disabled by customization!\n")
            logging.info('\nThe rules for ensure that systems Mandatory Access Controls are \
collected feature are already disabled by customization!\n')
        else:
            ensure_system_access()

def ensure_system_access():
    """This function ensure that system's Mandatory Access Controls are collected."""

    try:
        if os.path.exists("/etc/audit/rules.d/50-MAC_policy.rules") is True:
            logging.info('The directory is already present\n')
        else:
            os.system("touch /etc/audit/rules.d/50-MAC_policy.rules")
            logging.info('Successfully created the new directory\n')

        with open("/etc/audit/rules.d/50-MAC_policy.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        if '-w /etc/selinux/ -p wa -k MAC-policy' not in data and \
'-w /usr/share/selinux/ -p wa -k MAC-policy' not in data:
            os.system("echo -w /etc/selinux/ -p wa -k MAC-policy \
>> /etc/audit/rules.d/50-MAC_policy.rules")
            os.system("echo -w /usr/share/selinux/ -p wa -k MAC-policy \
>> /etc/audit/rules.d/50-MAC_policy.rules")
            print "\n**********Successfully ensured systems mandatory access controls \
are collected!**********\n"
            logging.info('Successfully ensured systems mandatory access controls are collected!\n')
        elif '-w /etc/selinux/ -p wa -k MAC-policy' in data and \
'-w /usr/share/selinux/ -p wa -k MAC-policy' in data:
            print "Systems mandatory access controls are already collected\n"
            logging.info('Systems mandatory access controls are already collected\n')
        else:
            logging.warning('Customized rule is found!!')

        os.system("service auditd restart > /dev/null 2>&1")
        logging.info('Restarting the auditd service!!')

    except IOError:
        logging.error('Script exited abnormally')

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_ensure_system_access.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'ensure_system_access.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        customized_system_access()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
