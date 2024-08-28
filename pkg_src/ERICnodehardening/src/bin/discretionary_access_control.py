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
# Name      : discretionary_access_control.py
# Purpose   : This script ensure discretionary access control permission
#             modification events are collected.
# Author    : ZBARPHU
# Reason    : EQEV-94615
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

def customized_disec_access():
    if not os.path.exists('/etc/audit/rules.d/50-perm_mod.rules'):
        disec_access()
    else:
        with open("/etc/audit/rules.d/50-perm_mod.rules", 'r') as fin:
            data = fin.read()
        cus_rules = ['#-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F \
auid!=4294967295 -k perm_mod', '#-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F \
auid>=1000 -F auid!=4294967295 -k perm_mod', '#-a always,exit -F arch=b64 -S chown -S fchown -S \
fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod', '#-a always,exit -F \
arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod', \
'#-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S \
lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod', '#-a always,exit -F \
arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F \
auid>=1000 -F auid!=4294967295 -k perm_mod']
        if any(rule in data for rule in cus_rules):
            print("\nThe rules for discretionary access control feature are already disabled by \
customization!\n")
            logging.info('\nThe rules for discretionary access control feature are already \
disabled by customization!\n')
        else:
            disec_access()

def disec_access():
    """This function ensure that discretionary access control permission modification \
events are collected."""

    try:
        if os.path.exists("/etc/audit/rules.d/50-perm_mod.rules") is True:
            logging.info('The file is already present in the directory!!\n')
        else:
            os.system("touch /etc/audit/rules.d/50-perm_mod.rules")
            logging.info('Successfully created the new file in the directory!!\n')

        with open("/etc/audit/rules.d/50-perm_mod.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        cmd = "getconf LONG_BIT"
        result = subprocess.check_output(cmd, shell=True)

        if int(result) == 64:
            if '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F \
auid!=4294967295 -k perm_mod' not in data and \
'-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F \
auid!=4294967295 -k perm_mod' not in data and \
'-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F \
auid>=1000 -F auid!=4294967295 -k perm_mod' not in data and \
'-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F \
auid>=1000 -F auid!=4294967295 -k perm_mod' not in data and \
'-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S \
lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' not in data and \
'-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S \
lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' not in data:
                os.system(r"echo -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F \
auid\>\=1000 -F auid!=4294967295 -k perm_mod >> /etc/audit/rules.d/50-perm_mod.rules")
                os.system(r"echo -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F \
auid\>\=1000 -F auid!=4294967295 -k perm_mod >> /etc/audit/rules.d/50-perm_mod.rules")
                os.system(r"echo -a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S \
lchown -F auid\>\=1000 -F auid!=4294967295 -k perm_mod >> /etc/audit/rules.d/50-perm_mod.rules")
                os.system(r"echo -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S \
lchown -F auid\>\=1000 -F auid!=4294967295 -k perm_mod >> /etc/audit/rules.d/50-perm_mod.rules")
                os.system(r"echo -a always,exit -F arch=b64 -S setxattr -S \
lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid\>\=1000 -F \
auid!=4294967295 -k perm_mod >> /etc/audit/rules.d/50-perm_mod.rules")
                os.system(r"echo -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S \
fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid\>\=1000 -F auid!=4294967295 -k \
perm_mod >> /etc/audit/rules.d/50-perm_mod.rules")
                print "\n**********Successfully the discretionary access control permission \
modification events are collected for 64 bit systems!**********\n"
                logging.info('Successfully the discretionary access control permission \
modification events are collected for 64 bit systems!\n')
            elif '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F \
auid>=1000 -F auid!=4294967295 -k perm_mod' in data and \
'-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F \
auid!=4294967295 -k perm_mod' in data and \
'-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F \
auid>=1000 -F auid!=4294967295 -k perm_mod' in data and \
'-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F \
auid>=1000 -F auid!=4294967295 -k perm_mod' in data and \
'-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S \
removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 \
-k perm_mod' in data and \
'-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S \
lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' in data:
                print "\n**********Successfully the discretionary access control permission \
modification events are already collected for 64 bit systems!**********\n"
                logging.info('Successfully the discretionary access control permission \
modification events are already collected for 64 bit systems!\n')
            else:
                logging.warning('Customized rule is found!!\n')
        elif int(result) == 32:
            if '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F \
auid>=1000 -F auid!=4294967295 -k perm_mod' not in data and \
'-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F \
auid!=4294967295 -k perm_mod' not in data and \
'-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S \
lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' not in data:
                os.system(r"echo -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat \
-F auid\>\=1000 -F auid!=4294967295 -k perm_mod >> /etc/audit/rules.d/50-perm_mod.rules")
                os.system(r"echo -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S \
lchown -F auid\>\=1000 -F auid!=4294967295 -k perm_mod >> /etc/audit/rules.d/50-perm_mod.rules")
                os.system(r"echo -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S \
fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid\>\=1000 -F auid!=4294967295 -k \
perm_mod >> /etc/audit/rules.d/50-perm_mod.rules")
                print "**********Successfully the discretionary access control permission \
modification events are already collected for 32 bit systems!**********"
                logging.info('Successfully the discretionary access control permission \
modification events are already collected for 32 bit systems!\n')
            elif '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F \
auid!=4294967295 -k perm_mod' in data and \
'-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F \
auid!=4294967295 -k perm_mod' in data and \
'-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S \
lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' in data:
                print "**********Successfully the discretionary access control permission \
modification events are already collected for 32 bit systems!**********"
                logging.info('Successfully the discretionary access control permission \
                modification events are already collected for 32 bit systems!\n')
            else:
                logging.warning('Customized rule is found!!\n')

        os.system("service auditd restart > /dev/null 2>&1")
        logging.info('Restarting the auditd service!!')

    except IOError:
        logging.error('Script exited abnormally')

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_discretionary_access_control.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'discretionary_access_control.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        customized_disec_access()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
