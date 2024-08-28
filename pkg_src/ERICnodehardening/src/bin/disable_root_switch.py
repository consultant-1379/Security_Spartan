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
# Name       : disable_root_switch.py
# Purpose    : This script disables user from using "sudo -i".
# Reason     : EQEV-111732
# Authour    : ZBARPHU
# Revision   : A
# ********************************************************************
"""

import subprocess
import os
import time
import logging

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from sentinel_hardening import log_func
from user_verification import user_verification

sudo = ["#%PAM-1.0", "auth       required        sudo", "account    sufficient      sudo", \
"password   include         sudo", "session    optional        pam_keyinit.so force revoke", \
"session    include         sudo"]

def sudo_switch():
    """This function disables root user switching for custom user"""
    try:
        backup_files('/etc/pam.d/sudo-i', [])
        data = subprocess.check_output("cat /etc/pam.d/sudo-i", \
shell=True, stderr=subprocess.STDOUT).strip()
        if all(word in data for word in sudo):
            print "\n**********Already restricted root user switching on the \
server!**********\n"
            logging.info('Already restricted root user switching on the server')
            return 1
        else:
            with open('/etc/pam.d/sudo-i', 'w') as f:
                for items in sudo:
                    f.write('%s\n' %items)
                print "\n**********Successfully restricted root user switching on the \
server!**********\n"
                logging.info('Successfully restricted root user switching on the server!')
            f.close()
            return 1
    except subprocess.CalledProcessError:
        print "\n**********Configuration file not found!**********\n"
        logging.error('Config file for root user switching not found on the server')
        return 0

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_disable_root_switch.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'disable_root_switch.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        sudo_switch()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
