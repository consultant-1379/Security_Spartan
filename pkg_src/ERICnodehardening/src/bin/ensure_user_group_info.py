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
# *********************************************************************
# Name      : ensure_user_group_info.py
# Purpose   : This script ensure events that modify user/group information
#             are collected.
# Author    : ZBARPHU
# Reason    : EQEV-100748
#
# *********************************************************************
"""
import subprocess
import os
import time
import logging
import getpass

from Verify_NH_Config import configure_nh
from sentinel_hardening import log_func
from user_verification import user_verification

def customized_user_group_info():
    if not os.path.exists('/etc/audit/rules.d/50-identity.rules'):
        user_group_info()
    else:
        with open("/etc/audit/rules.d/50-identity.rules", 'r') as fin:
            data = fin.read()

        cus_rules = ['#-w /etc/group -p wa -k identity', '#-w /etc/passwd -p wa -k identity', \
'#-w /etc/gshadow -p wa -k identity', '#-w /etc/shadow -p wa -k identity', \
'#-w /etc/security/opasswd -p wa -k identity']

        if any(rule in data for rule in cus_rules):
            print("\nThe rules for ensure events that modify user/group information are collected \
feature are already disabled by customization!\n")
            logging.info('\nThe rules for ensure events that modify user/group information are \
collected feature are already disabled by customization!\n')
        else:
            user_group_info()

def user_group_info():
    """This function ensure events that modify user/group information are collected."""

    try:
        if os.path.exists("/etc/audit/rules.d/50-identity.rules") is True:
            logging.info("The file is already present in the directory!!\n")
        else:
            os.system("touch /etc/audit/rules.d/50-identity.rules")
            logging.info("Successfully created the new file in the directory!!\n")

        with open("/etc/audit/rules.d/50-identity.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        if '-w /etc/group -p wa -k identity' not in data and \
'-w /etc/passwd -p wa -k identity' not in data and \
'-w /etc/gshadow -p wa -k identity' not in data and \
'-w /etc/shadow -p wa -k identity' not in data and \
'-w /etc/security/opasswd -p wa -k identity' not in data:
            os.system(r"echo -w /etc/group -p wa -k identity >> /etc/audit/rules.d/\
50-identity.rules")
            os.system(r"echo -w /etc/passwd -p wa -k identity >> /etc/audit/rules.d/\
50-identity.rules")
            os.system(r"echo -w /etc/gshadow -p wa -k identity >> /etc/audit/rules.d/\
50-identity.rules")
            os.system(r"echo -w /etc/shadow -p wa -k identity >> /etc/audit/rules.d/\
50-identity.rules")
            os.system(r"echo -w /etc/security/opasswd -p wa -k identity >> /etc/audit/rules.d/\
50-identity.rules")
            print "\n\n**********Successfully ensured events that modify user/group \
information are collected!**********\n\n"
            logging.info('Successfully ensured events that modify user/group \
information are collected!\n')
        elif "-w /etc/group -p wa -k identity" in data and \
'-w /etc/passwd -p wa -k identity' in data and \
'-w /etc/gshadow -p wa -k identity' in data and \
'-w /etc/shadow -p wa -k identity' in data and \
'-w /etc/security/opasswd -p wa -k identity' in data:
            print "\n\n**********Successfully ensured events that modify user/group \
information are already collected!**********\n\n"
            logging.info('Successfully ensured events that modify user/group \
information are already collected\n')
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
    FNAME = TIMESTR + '_ensure_user_group_info.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'ensure_user_group_info'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        customized_user_group_info()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
