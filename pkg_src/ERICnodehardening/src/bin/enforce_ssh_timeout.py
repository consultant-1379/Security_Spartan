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
# Name      : enforce_ssh_timeout.py
# Purpose   : This script sets the SSH Idle Timeout Interval by configuring
#             ClientAliveCountMax and ClientAliveInterval
# Reason    : EQEV-92524
# Revision  : A
# ********************************************************************
"""
import subprocess
import time
import logging
import os
import getpass

from sentinel_hardening import log_func
from NH_Backup import backup_files
from Verify_NH_Config import configure_nh
from user_verification import user_verification

def ssh_timeout():
    """This function sets SSH idle timeout session as per recommendation"""
    flag1 = 0
    flag2 = 0
    sshd_file = '/etc/ssh/sshd_config'
    backup_files(sshd_file, [])
    fin = open(sshd_file, 'r')
    filecontent = fin.read()
    fin.close()
    try:
        if 'ClientAliveInterval 300\n' in filecontent:
            filecontent = filecontent.replace("ClientAliveInterval 300", "ClientAliveInterval 900")
            flag1 = 1

        if 'ClientAliveInterval' in open(sshd_file).read():
            if '#ClientAliveInterval 0\n' in filecontent:
                filecontent = filecontent\
                    .replace("#ClientAliveInterval 0", "ClientAliveInterval 900")
                flag1 = 1
            elif 'ClientAliveInterval 900\n' in filecontent:
                print '\n**********Client Interval has been set already!**********\n'
                logging.info('Client Interval has been set already')
            else:
                logging.warning("Customized value found for client Interval time")
        else:
            filecontent = filecontent+"\nClientAliveInterval 900\n"
            flag1 = 1
        if 'ClientAliveCountMax' in open(sshd_file).read():
            if '#ClientAliveCountMax 3\n' in filecontent:
                filecontent = filecontent.replace("#ClientAliveCountMax 3", "ClientAliveCountMax 0")
                flag2 = 1
            elif 'ClientAliveCountMax 0\n' in filecontent:
                print '\n**********Maximum Counts has been set already!**********\n'
                logging.info('Maximum counts has been set already')
            else:
                logging.warning("Customized value found for Maximum counts")
        else:
            filecontent = filecontent+"\nClientAliveCountMax 0\n"
            flag2 = 1

        if 'ClientAliveCountMax 3\n' in filecontent:
            filecontent = filecontent.replace("ClientAliveCountMax 3", "ClientAliveCountMax 0")
            flag2 = 1

        if (flag1 == 1) or (flag2 == 1) or (flag1 == 1 and flag2 == 1):
            with open('/etc/ssh/sshd_config', 'w') as fout:
                fout.write(''.join(filecontent))
            print "\n**********Successfully set SSH Time out value!**********\n"
            logging.info('**********Successfully set SSH Time out value!**********')
    except IOError:
        print "\nScript exited abnormally...!!!"
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)

    subprocess.call('systemctl restart sshd', shell=True)

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_enforce_ssh_timeout.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'enforce_ssh_timeout.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        ssh_timeout()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
