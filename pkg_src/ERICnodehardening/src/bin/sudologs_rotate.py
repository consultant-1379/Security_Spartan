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
# Name       : sudologs_rotate.py
# Purpose    : This script configures logrotate for sudo log.
# Reason     : EQEV-111556
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


def del_sudo_log():
    try:
        """This function is deletes the existing log rotation for sudo log"""
        backup_files("/etc/logrotate.d/syslog", [])
        with open("/etc/logrotate.d/syslog", 'r') as fin:
            data = fin.read()
        data = data.strip().split()
        if "/var/log/sudo.log" in data:
            os.system("sed -i 's/\S*\(sudo.log\)\S*//g' /etc/logrotate.d/syslog")
            os.system("sed -i \'/^$/d\' /etc/logrotate.d/syslog")
            logging.info('Successfully removed existing log rotation for sudo log!\n')
    except IOError:
        print "\n**********Log rotation file not found for existing configuration!**********\n"
        logging.error('Log rotation file not found for existing configuration!\n')

def sudo_log_contents():
    """This function writes the sudo log rotation configuration in the config file"""
    with open("/etc/logrotate.d/sudo", 'r') as fin:
        data = fin.read()
    data = data.split('\n')
    con = ['/var/log/sudo.log','{','    daily','    compress','    size 20M','    rotate 1',\
'    create','    dateext','    postrotate','        systemctl restart rsyslog',\
'    endscript','}']
    if all(word in data for word in con):
        print "\n**********Already enabled log rotation for sudo log!**********\n"
        logging.info('Already enabled log rotation for sudo log!')
    else:
        with open('/etc/logrotate.d/sudo', 'w') as f:
            for items in con:
                f.write('%s\n' %items)
            print "\n**********Successfully enabled log rotation for sudo log!**********\n"
            logging.info('Successfully enabled log rotation for sudo log!')
        f.close()

def sudo_log():
    """This function checks for the presence of configuration file for sudo log"""
    del_sudo_log()
    if os.path.exists('/etc/logrotate.d/sudo') == False:
        subprocess.call('touch /etc/logrotate.d/sudo', shell=True)
        subprocess.call('chmod 644 /etc/logrotate.d/sudo', shell=True)
        sudo_log_contents()
    else:
        sudo_log_contents()

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_sudologs_rotate.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'sudologs_rotate.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        sudo_log()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)