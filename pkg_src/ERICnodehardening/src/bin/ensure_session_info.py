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
# Name      : ensure_session_info.py
# Purpose   : This script ensures audit session initiation information
#             are collected.
# Author    : ZBARPHU
# Reason    : EQEV-124639
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

def customized_session_info():
    """This function verifies that any customized rules are found for the feature."""
    if not os.path.exists('/etc/audit/rules.d/50-session.rules'):
        session_info()
    else:
        with open("/etc/audit/rules.d/50-session.rules", 'r') as fin:
            data = fin.read()
        cus_rules = ['#-w /var/run/utmp -p wa -k session', \
'#-w /var/log/wtmp -p wa -k logins', '#-w /var/log/btmp -p wa -k login']
        if any(rule in data for rule in cus_rules):
            print("\nThe rules for capturing session initiation information \
feature were found to be customized!\n")
            logging.info('The rules for capturing session initiation information \
feature were found to be customized!\n')
        else:
            session_info()

def session_info():
    """This function ensure that session initiation information events are collected."""

    try:
        if os.path.exists("/etc/audit/rules.d/50-session.rules") is True:
            logging.info('The file is already present in the directory!!\n')
        else:
            os.system("touch /etc/audit/rules.d/50-session.rules")
            logging.info('Successfully created the new file in the directory!!\n')
        with open("/etc/audit/rules.d/50-session.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        rules = ['-w /var/run/utmp -p wa -k session', \
'-w /var/log/wtmp -p wa -k logins', '-w /var/log/btmp -p wa -k logins']
        if all(rule in data for rule in rules):
            print "\n\n**********Audit rules to collect session initiation \
events are enabled**********\n\n"
            logging.info('Audit rules to collect session initiation information \
are enabled!\n')
        elif any(rule not in data for rule in rules):
            if os.path.getsize("/etc/audit/rules.d/50-session.rules") == 0:
                os.system(r"echo -w /var/run/utmp -p wa -k session \
>> /etc/audit/rules.d/50-session.rules")
                os.system(r"echo -w /var/log/wtmp -p wa -k logins \
>> /etc/audit/rules.d/50-session.rules")
                os.system(r"echo -w /var/log/btmp -p wa -k logins \
>> /etc/audit/rules.d/50-session.rules")
                print "\n\n**********Successfully enabled audit rules to collect session \
initiation information**********\n\n"
                logging.info('Successfully enabled audit rules to collect session initiation \
information!\n')
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
    FNAME = TIMESTR + '_ensure_audit_session_info.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'ensure_audit_session_info.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        customized_session_info()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
