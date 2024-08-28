#!/usr/bin/python
"""
# ****************************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ****************************************************************************
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
# ******************************************************************************
# Name        : set_path_integrity.py
# Author      : Pradeep Kumar (ZDODPRA)
# Purpose     : This is to ensure root PATH integrity.
# Date        : 02-07-2021
# Revision    : A
# Reason      : EQEV-90265
# ******************************************************************************
"""
import os
import getpass
import subprocess
import time
import logging
from Verify_NH_Config import configure_nh
from sentinel_hardening import log_func
from NH_Backup import backup_files
from user_verification import user_verification
def verify_path():
    """This function ensures root PATH integrity"""
    backup_files('/root/.bash_profile', [])
    try:
        with open("/root/.bash_profile", 'r') as fin:
            data = fin.readlines()
        set_path = "PATH=$PATH:$HOME/bin\n"
        export_path = "export PATH\n"
        flag = 0
        if "#PATH=$PATH:$HOME/bin\n" not in data and "#export PATH\n" not in data:
            if set_path not in data and export_path not in data:
                logging.info("Defualt parameters are missing")
            else:
                for i in data:
                    temp = data.index(i)
                    if data[temp] == set_path:
                        data[temp] = "#PATH=$PATH:$HOME/bin\n"
                        flag = flag+1
                    elif data[temp] == export_path:
                        data[temp] = "#export PATH\n"
                        flag = flag+1
        else:
            print"*******************/root/bin dir has already been removed to " \
                 "ensure root PATH integrity*******************"
            logging.info("/root/bin dir has already been removed to\
 ensure root PATH integrity")
        with open("/root/.bash_profile", 'w') as fout:
            fout.writelines(''.join(data))
        if flag == 1 or flag == 2:
            print"*******************Successfully removed /root/bin dir to ensure \
root PATH integrity*******************"
            logging.info("Successfully removed /root/bin dir to ensure root PATH integrity")
    except (IOError, RuntimeError):
        print"Could not ensure the root PATH inegrity"
        logging.error("Coul not ensure the root PATH inegrity")
if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + 'set_path_integrity.log'
    os.system("mkdir -p /ericsson/security/log/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,\
filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,\
format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'set_path_integrity.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        verify_path()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
