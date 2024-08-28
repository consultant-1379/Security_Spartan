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
# Name      : ensure_auditconf_immutable.py
# Purpose   : This script ensures that audit configuration is immutable.
# Author    : ZBARPHU
# Reason    : EQEV-95305
#
# ********************************************************************
"""
import subprocess
import os
import time
import logging
import getpass

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from sentinel_hardening import log_func
from reboot import reboot
from user_verification import user_verification

def immutable_auditconf():
    """This function ensures that audit configuration is immutable."""

    try:
        if os.path.exists("/etc/audit/rules.d/99-finalize.rules") is True:
            logging.info("The file is already present in the directory!!\n")
        else:
            os.system("touch /etc/audit/rules.d/99-finalize.rules")
            logging.info("Successfully created the new file in the directory!!\n")

        with open("/etc/audit/rules.d/99-finalize.rules", 'r') as fin:
            data = fin.read()
        data = data.split('\n')

        if '-e 2' not in data:
            if '-e 1' in data or \
'-e 0' in data:
                logging.warning('Customized value found!!!\n')
            else:
                os.system("echo \"-e 2\" >> /etc/audit/rules.d/99-finalize.rules")
                print "\n**********Successfully ensured audit configuration is \
immutable!**********\n"
                logging.info('Successfully ensured audit configuration is immutable!!\n')
        elif '-e 2' in data:
            print "\n**********Already ensured the audit configuration in immutable!**********\n"
            logging.warning('Already ensured the audit configuration in immutable!!\n')
        else:
            logging.warning('\nCustomized value found!!\n')

        os.system("service auditd restart > /dev/null 2>&1")
        logging.info('Restarting the auditd service!!')

    except IOError:
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)

if __name__ == '__main__':
    user_verification()
    print "\nNOTE: This script execution reqires server reboot!!\n"
    DISPLAY = raw_input("\033[93m\"Do you still want to proceed? (y/n)?\":\033[00m")
    if (DISPLAY == 'n') or (DISPLAY == 'N'):
        exit(1)
    elif (DISPLAY == 'y') or (DISPLAY == 'Y'):
        print"\n"
    else:
        print "Invalid Option\n"
        exit(1)
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_ensure_auditconf_immutable.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'ensure_auditconf_immutable.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        immutable_auditconf()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
    reboot()