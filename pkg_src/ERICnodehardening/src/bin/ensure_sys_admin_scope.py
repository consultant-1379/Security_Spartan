#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2022 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : ensure_sys_admin_scope.py
# Purpose   : This script ensure changes to system administration
#             scope (sudoers) is collected
# Author    : ZBARPHU
# Reason    : EQEV-100747
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

def customized_sys_admin_scope():
    if not os.path.exists('/etc/audit/rules.d/50-scope.rules'):
        sys_admin_scope()
    else:
        with open("/etc/audit/rules.d/50-scope.rules", 'r') as fin:
            data = fin.read()
        cus_rules = ['#-w /etc/sudoers -p wa -k scope', '#-w /etc/sudoers.d/ -p wa -k scope']
        if any(rule in data for rule in cus_rules):
            print("\nThe rules for ensure changes to system administration scope (sudoers) is \
collected feature are already disabled by customization!\n")
            logging.info('\nThe rules for ensure changes to system administration scope (sudoers) \
is collected feature are already disabled by customization!\n')
        else:
            sys_admin_scope()

def sys_admin_scope():
    """This function ensure changes to system administration scope (sudoers) is collected."""

    try:
        if os.path.exists("/etc/audit/rules.d/50-scope.rules") is True:
            logging.info("The file is already present in the directory!!\n")
        else:
            os.system("touch /etc/audit/rules.d/50-scope.rules")
            logging.info("Successfully created the new file in the directory!!\n")

        with open("/etc/audit/rules.d/50-scope.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        if '-w /etc/sudoers -p wa -k scope' not in data and \
'-w /etc/sudoers.d/ -p wa -k scope' not in data:
            os.system(r"echo -w /etc/sudoers -p wa -k scope >> /etc/audit/rules.d/50-scope.rules")
            os.system(r"echo -w /etc/sudoers.d/ -p wa -k scope >> /etc/audit/rules.d/\
50-scope.rules")
            print "\n\n**********Successfully ensured changes to system administration scope \
(sudoers) logs are collected!**********\n\n"
            logging.info('Successfully ensured changes to system administration scope (sudoers) '
                         'logs are collected!\n')
        elif '-w /etc/sudoers -p wa -k scope' in data and \
'-w /etc/sudoers.d/ -p wa -k scope' in data:
            print "\n\n**********Successfully ensured changes to system administration scope \
(sudoers) logs are already collected!**********\n\n"
            logging.info('Successfully ensured changes to system administration scope (sudoers) '
                         'logs are already collected\n')
        else:
            logging.warning('Customized rule is found!!\n')

        os.system("service auditd restart > /dev/null 2>&1")
        logging.info('Restarting the auditd service!!\n')

    except IOError:
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_ensure_sys_admin_scope.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'ensure_sys_admin_scope'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        customized_sys_admin_scope()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
