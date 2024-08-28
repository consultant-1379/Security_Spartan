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
# Name      : ensure_kernel_module.py
# Purpose   : This script ensures that kernel module loading and unloading
#             is collected.
# Author    : ZATLPOE
# Reason    : EQEV-95304
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

def customized_kernel_module():
    if not os.path.exists('/etc/audit/rules.d/50-modules.rules'):
        ensure_kernel_module()
    else:
        with open("/etc/audit/rules.d/50-modules.rules", 'r') as fin:
            data = fin.read()
        cus_rules = ['#-w /sbin/insmod -p x -k modules', '#-w /sbin/rmmod -p x -k modules', \
'#-w /sbin/modprobe -p x -k modules', '#-a always,exit -F arch=b64 -S init_module -S \
delete_module -k modules']

        if any(rule in data for rule in cus_rules):
            print("The rules for kernel module loading and unloading is collected feature \
are already disabled by customization!")
            logging.info('The rules for kernel module loading and unloading is collected feature \
are already disabled by customization!')
        else:
            ensure_kernel_module()

def ensure_kernel_module():
    """This function ensure that kernel module loading and unloading is collected."""

    try:
        if os.path.exists("/etc/audit/rules.d/50-modules.rules") is True:
            logging.info('The directory is already present\n')
        else:
            os.system("touch /etc/audit/rules.d/50-modules.rules")
            logging.info('Successfully created the new directory\n')

        with open("/etc/audit/rules.d/50-modules.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        cmd = "getconf LONG_BIT"
        result = subprocess.check_output(cmd, shell=True)

        if int(result) == 64:
            if '-w /sbin/insmod -p x -k modules' in data and '-w /sbin/rmmod -p x -k modules' \
in data and '-w /sbin/modprobe -p x -k modules' in data and '-a always,exit -F arch=b64 -S \
init_module -S delete_module -k modules' in data:
                print "Kernel module loading and unloading is already collected\n"
                logging.info('Kernel module loading and unloading is already collected\n')
            elif '-w /sbin/insmod -p x -k modules' not in data and \
'-w /sbin/rmmod -p x -k modules' not in data and '-w /sbin/modprobe -p x -k modules' not in data \
and '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules' not in data:
                os.system(r"echo -w /sbin/insmod -p x -k modules \
>> /etc/audit/rules.d/50-modules.rules")
                os.system(r"echo -w /sbin/rmmod -p x -k modules \
>> /etc/audit/rules.d/50-modules.rules")
                os.system(r"echo -w /sbin/modprobe -p x -k modules \
>> /etc/audit/rules.d/50-modules.rules")
                os.system(r"echo -a always,exit -F arch=b64 -S init_module -S delete_module \
-k modules >> /etc/audit/rules.d/50-modules.rules")
                print "\n**********Successfully ensured that kernel module loading and unloading \
is collected!**********\n"
                logging.info('Successfully ensured that kernel module loading and unloading is \
collected!\n')
            else:
                logging.warning('Customized rule is found!!\n')
        elif int(result) == 32:
            if '-w /sbin/insmod -p x -k modules' in data and '-w /sbin/rmmod -p x -k modules' \
in data and '-w /sbin/modprobe -p x -k modules' in data and '-a always,exit -F arch=b32 -S \
init_module -S delete_module -k modules' in data:
                print "Kernel module loading and unloading is already collected\n"
                logging.info('Kernel module loading and unloading is already collected\n')
            elif '-w /sbin/insmod -p x -k modules' not in data and \
'-w /sbin/rmmod -p x -k modules' not in data and '-w /sbin/modprobe -p x -k modules' not in data \
and '-a always,exit -F arch=b32 -S init_module -S delete_module -k modules' not in data:
                os.system(r"echo -w /sbin/insmod -p x -k modules \
>> /etc/audit/rules.d/50-modules.rules")
                os.system(r"echo -w /sbin/rmmod -p x -k modules \
>> /etc/audit/rules.d/50-modules.rules")
                os.system(r"echo -w /sbin/modprobe -p x -k modules \
>> /etc/audit/rules.d/50-modules.rules")
                os.system(r"echo -a always,exit -F arch=b32 -S init_module -S delete_module \
-k modules >> /etc/audit/rules.d/50-modules.rules")
                print "\n**********Successfully ensured that kernel module loading and unloading \
is collected!**********\n"
                logging.info('Successfully ensured that kernel module loading and unloading is \
collected!\n')
            else:
                logging.warning('Customized rule is found!!\n')

        os.system("service auditd restart > /dev/null 2>&1")
        logging.info('Restarting the auditd service!!')
    except IOError:
        logging.error('Script exited abnormally')

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_ensure_kernel_module.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'ensure_kernel_module.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        customized_kernel_module()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
