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
# Name      : pwd_creation_policies.py
# Purpose   : This script ensures password creation requirements are
#             configured or not.
# Reason    : EQEV-96929
# Author    : zdodpra
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

def pwd_creation():
    """This function ensures password creation requirements are configured"""
    try:
        with open("/etc/security/pwquality.conf", 'r') as in_file:
            data4 = in_file.read()

        pwd_auth = '/etc/pam.d/password-auth'
        with open(pwd_auth) as fin:
            data = fin.read().replace('password    requisite     pam_pwquality.so try_first_pass local_users_only \
retry=3 authtok_type=', 'password    requisite     pam_pwquality.so try_first_pass minlen = 14 maxrepeat=2 \
dcredit = -1 ucredit = -1 ocredit = -1 lcredit = -1 ... enforce_for_root     retry=3')
        with open(pwd_auth, 'w') as fout:
            fout.write(data)
        with open(pwd_auth) as fin1:
            data1 = fin1.read().replace('password    requisite     pam_pwquality.so minlen=9 maxrepeat=2 lcredit=-1 \
ucredit=-1 dcredit=-1 ocredit=-1 ... enforce_for_root retry=3', 'password    requisite     pam_pwquality.\
so try_first_pass minlen = 14 maxrepeat=2 dcredit = -1 ucredit = -1 ocredit = -1 \
lcredit = -1 ... enforce_for_root     retry=3')
        with open(pwd_auth, 'w') as fout1:
            fout1.write(data1)

        data2 = ""
        line1 = 0
        with open("/etc/pam.d/system-auth", 'r') as fin2:
            data2 = fin2.readlines()
        for i in data2:
            if i == "account     required      pam_permit.so\n":
                line1 = data2.index(i)
                pwd_req = 'password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 \
authtok_type=\n'
                if data2[line1+2] == pwd_req:
                    data2.pop(line1+2)
                if 'password    requisite     pam_pwquality.so try_first_pass minlen = 14 maxrepeat=2 dcredit = -1 \
ucredit = -1 ocredit = -1 lcredit = -1 ... enforce_for_root     retry=3\n' not in data2 and 'password    \
requisite     pam_pwquality.so minlen=9 maxrepeat=2 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1 ... enforce_for_root \
retry=3\n' not in data2:
                    data2.insert(line1+2, 'password    requisite     pam_pwquality.so try_first_pass minlen = 14 \
maxrepeat=2 dcredit = -1 ucredit = -1 ocredit = -1 lcredit = -1 ... enforce_for_root     retry=3\n')
                if pwd_req not in data2:
                    data2.insert(line1+4, pwd_req)
        with open("/etc/pam.d/system-auth", 'w') as fout2:
            fout2.writelines(''.join(data2))

        with open('/etc/pam.d/system-auth') as fin3:
            data3 = fin3.read().replace('password    requisite     pam_pwquality.so minlen=9 maxrepeat=2 lcredit=-1 \
ucredit=-1 dcredit=-1 ocredit=-1 ... enforce_for_root retry=3', 'password    requisite     \
pam_pwquality.so try_first_pass minlen = 14 maxrepeat=2 dcredit = -1 ucredit = -1 ocredit = -1 \
lcredit = -1 ... enforce_for_root     retry=3')
        with open('/etc/pam.d/system-auth', 'w') as fout3:
            fout3.write(data3)

        if 'minlen = 14' in data4 and 'dcredit = -1' in data4 and 'ucredit = -1' in data4 \
 and 'ocredit = -1' in data4 and 'lcredit = -1' in data4:
            print "\n**********Password parameters values are already been set*********\n"
            logging.info('Password parameters values are already been set!')
        elif '# minlen = 9' not in data4 and '# dcredit = 1' not in data4 and '# ucredit = 1' not in data4 and \
'# ocredit = 1' not in data4 and '# lcredit = 1' not in data4:
                logging.warning('Default parameter is not found')
        else:
            data4 = data4.replace("# minlen = 9", "minlen = 14")
            data4 = data4.replace("# dcredit = 1", "dcredit = -1")
            data4 = data4.replace("# ucredit = 1", "ucredit = -1")
            data4 = data4.replace("# ocredit = 1", "ocredit = -1")
            data4 = data4.replace("# lcredit = 1", "lcredit = -1")
            fout = open('/etc/security/pwquality.conf', 'w')
            fout.write(data4)
            fout.close()
            print "\n**********Successfully set Password parameter values*********\n"
            logging.info('Successfully set Password parameter values!')
    except IOError:
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + 'pwd_creation_policies.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'pwd_creation_policies.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        pwd_creation()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
