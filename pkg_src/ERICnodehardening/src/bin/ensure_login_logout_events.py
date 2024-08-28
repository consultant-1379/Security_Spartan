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
# Name      : ensure_login_logout_events.py
# Purpose   : This script ensure audit login and logout events
#             are collected.
# Author    : ZBARPHU
# Reason    : EQEV-124638
#
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

def customized_login_logout():
    """This function verifies that any customized rules are found for the feature."""
    if not os.path.exists('/etc/audit/rules.d/50-logins.rules'):
        login_logout()
    else:
        with open("/etc/audit/rules.d/50-logins.rules", 'r') as fin:
            data = fin.read()
        cus_rules = ['#-w /var/log/lastlog -p wa -k logins', \
'#-w /var/run/faillock/ -p wa -k logins']
        if any(rule in data for rule in cus_rules):
            print("\nThe audit rules for capturing login and logout events are \
collected feature were found to be customized!\n")
            logging.info('The audit rules for capturing login and logout events \
are collected feature were found to be customized!\n')
        else:
            login_logout()

def login_logout():
    """This function ensure that login and logout events are collected."""

    try:
        if os.path.exists("/etc/audit/rules.d/50-logins.rules") is True:
            logging.info('The file is already present in the directory!!\n')
        else:
            os.system("touch /etc/audit/rules.d/50-logins.rules")
            logging.info('Successfully created the new file in the directory!!\n')

        with open("/etc/audit/rules.d/50-logins.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        rules = ['-w /var/log/lastlog -p wa -k logins', \
'-w /var/run/faillock/ -p wa -k logins']
        if all(rule in data for rule in rules):
            print "\n\n**********Audit rules for capturing login and logout \
events are already enforced**********\n\n"
            logging.info('Audit rules for capturing login and logout events are already enforced!')
        elif any(rule not in data for rule in rules):
            if os.path.getsize("/etc/audit/rules.d/50-logins.rules") == 0:
                os.system(r"echo -w /var/log/lastlog -p wa -k logins \
>> /etc/audit/rules.d/50-logins.rules")
                os.system(r"echo -w /var/run/faillock/ -p wa -k logins \
>> /etc/audit/rules.d/50-logins.rules")
                print "**********Successfully enabled audit rules to collect login and logout \
events**********"
                logging.info('Successfully enabled audit rules to collect login and logout \
events!\n')
            else:
                print "Manual customization found"
                logging.info('Manual customization found')
        os.system("service auditd restart > /dev/null 2>&1")
        logging.info('Restarting the auditd service!!')
    except IOError:
        logging.error('Script exited abnormally')

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_ensure_audit_login_logout_events.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'ensure_audit_login_logout_events.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        customized_login_logout()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
