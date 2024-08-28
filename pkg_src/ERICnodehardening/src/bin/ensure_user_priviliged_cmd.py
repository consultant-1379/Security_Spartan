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
# *********************************************************************
# Name      : ensure_user_priviliged_cmd.py
# Purpose   : This script ensures the use of privileged commands
              is collected.
# Author    : ZBARPHU
# Reason    : EQEV-95303
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

def customized_user_priviliged_cmd():
    if not os.path.exists('/etc/audit/rules.d/50-privileged.rules'):
        user_priviliged_cmd()
    else:
        with open("/etc/audit/rules.d/50-privileged.rules", 'r') as fin:
            data = fin.read()
        lines = data.splitlines()

        if any(line.startswith("#") for line in lines):
            print("The rules for ensuring the use of privileged commands collection feature \
are already disabled by customization!")
            logging.info("The rules for ensuring the use of privileged commands collection feature \
are already disabled by customization!")
        else:
            user_priviliged_cmd()

def user_priviliged_cmd():
    """This function ensures the use of privileged commands is collected."""

    try:
        if os.path.exists("/etc/audit/rules.d/50-privileged.rules") is True:
            logging.info("The file is already present in the directory!!\n")
        else:
            os.system("touch /etc/audit/rules.d/50-privileged.rules")
            logging.info("Successfully created the new file in the directory!!\n")

        with open("/etc/audit/rules.d/50-privileged.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        if os.path.getsize('/etc/audit/rules.d/50-privileged.rules') == 0:
            os.system(r"""find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk \
'{print "-a always,exit -F path=" $1 " -F perm=x -F auid>='"$(awk '/^\s*UID_MIN/{print $2}' \
/etc/login.defs)"' -F auid!=4294967295 -k privileged" }' \
>> /etc/audit/rules.d/50-privileged.rules""")
            print "\n\n**********Successfully ensured the use of privileged commands is \
collected!**********\n\n"
            logging.info('Successfully ensured the use of privileged commands is collected!\n')
        else:
            print "\n\n**********Successfully ensured the use of privileged commands is \
already collected!**********\n\n"
            logging.info('Successfully ensured the use of privileged commands is already \
collected!\n')

        os.system("service auditd restart > /dev/null 2>&1")
        logging.info('Restarting the auditd service!!\n')

    except IOError:
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_ensure_user_priviliged_cmd.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'ensure_user_priviliged_cmd.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        customized_user_priviliged_cmd()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
