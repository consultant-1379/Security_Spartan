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
# Name      : password_policies_rollback.py
# Purpose   : This script restores the default password policies as
#             recommended by RHEL
# Reason    : EQEV-96929
# Author    : ZDODPRA
# Revision  : A
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
from user_verification import user_verification

def pwd_creation_rollback():
    """This function ensures password creation requirements are configured"""
    with open("/etc/security/pwquality.conf", 'r') as in_file:
        data4 = in_file.read()
    try:
        with open('/etc/pam.d/password-auth') as fin:
            data = fin.read().replace('password    requisite     \
pam_pwquality.so try_first_pass minlen = 14 maxrepeat=2 dcredit = -1 ucredit = -1 ocredit = -1 \
lcredit = -1 ... enforce_for_root     retry=3','password    requisite     \
pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=')
        with open('/etc/pam.d/password-auth', 'w') as fout:
            fout.write(data)

        with open('/etc/pam.d/system-auth') as fin3:
            data3 = fin3.read().replace('password    requisite     \
pam_pwquality.so try_first_pass minlen = 14 maxrepeat=2 dcredit = -1 ucredit = -1 ocredit = -1 \
lcredit = -1 ... enforce_for_root     retry=3', 'password    requisite     \
pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=')
        with open('/etc/pam.d/system-auth', 'w') as fout3:
            fout3.write(data3)

        if 'minlen = 14' in data4 and 'dcredit = -1' in data4 and 'ucredit = -1' in data4 \
 and 'ocredit = -1' in data4 and 'lcredit = -1' in data4:
            print "\n**********Password parameters values are already been set*********\n"

            data4 = data4.replace("minlen = 14", "# minlen = 9")
            data4 = data4.replace("dcredit = -1", "# dcredit = 1")
            data4 = data4.replace("ucredit = -1", "# ucredit = 1")
            data4 = data4.replace("ocredit = -1", "# ocredit = 1")
            data4 = data4.replace("lcredit = -1", "# lcredit = 1")
            fout = open('/etc/security/pwquality.conf', 'w')
            fout.write(data4)
            fout.close()
            print "\n**********Successfully reset Password parameter values*********\n"
            logging.info('Successfully reset Password parameter values!')
    except IOError:
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + 'password_policies_rollback.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'password_policies_rollback.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        pwd_creation_rollback()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
