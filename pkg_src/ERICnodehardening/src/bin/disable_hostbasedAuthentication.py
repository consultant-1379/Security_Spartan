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
# Name      : disable_hostbasedAuthentication.py
# Purpose   : This script ensures that SSH HostBasedAuthentication
#             is disabled.
# Author    : ZATLPOE
# Reason    : EQEV-96569
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
from NH_Backup import backup_files
from user_verification import user_verification

def disable_hostbased_authentication():
    """This function ensure that SSH HostBasedAuthentication is disabled."""
    sshd_config = '/etc/ssh/sshd_config'
    backup_files(sshd_config, [])

    try:
        with open(sshd_config) as fin:
            data = fin.read()
        data = data.split('\n')
        new_config = ""
        host_no = 'HostbasedAuthentication no'
        with open(sshd_config) as fin:
            if 'HostbasedAuthentication yes' in data:
                logging.warning('Customized value found!')
            elif host_no not in data:
                if '#HostbasedAuthentication no' in data:
                    new_config = fin.read().replace('#HostbasedAuthentication no', host_no)
                    print "\n**********Successfully ensure SSH HostBasedAuthentication \
is disabled**********"
                    logging.info('Successfully ensure SSH HostBasedAuthentication is disabled')
                elif '#HostbasedAuthentication yes' in data:
                    new_config = fin.read().replace('#HostbasedAuthentication yes', host_no)
                    print "\n**********Successfully ensure SSH HostBasedAuthentication \
is disabled**********\n"
                    logging.info('Successfully ensure SSH HostBasedAuthentication is disabled\n')
                else:
                    os.system("echo HostbasedAuthentication no >> /etc/ssh/sshd_config")
                    print "\n**********Successfully ensure SSH HostBasedAuthentication \
is disabled**********\n"
                    logging.info('Successfully ensure SSH HostBasedAuthentication is disabled\n')
            elif host_no in data:
                print "\n*********Already ensure SSH HostBasedAuthentication is disabled*********\n"
                logging.info('Already ensure SSH HostBasedAuthentication is disabled\n')

        if new_config:
            with open(sshd_config, "w") as fout:
                fout.write(new_config)
    except IOError:
        logging.error('Script exited abnormally')

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_disable_hostbasedAuthentication.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'disable_hostbasedAuthentication.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        disable_hostbased_authentication()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
