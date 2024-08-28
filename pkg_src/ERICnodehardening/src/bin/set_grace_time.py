#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2019 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : set_grace_time.py
# Purpose   : This script sets the grace time to 60 seconds for
#               any new terminal.
# Reason    : EQEV-92525
# Revision  : B
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

def ssh_login():
    """This function sets the grace time to 1 minute for any new terminal."""

    backup_files('/etc/ssh/sshd_config', [])
    flag = 0
    A = '/etc/ssh/sshd_config'
    fin = open(A, 'r')
    filecontent = fin.read()
    fin.close()
    try:
        if 'LoginGraceTime' in open(A).read():
            if filecontent.find('LoginGraceTime 2m') != -1:
                filecontent = filecontent.replace("#LoginGraceTime 2m", "LoginGraceTime 1m")
                filecontent = filecontent.replace("LoginGraceTime 2m", "")
                flag = 1
            elif filecontent.find('LoginGraceTime 1m') != -1:
                print '\n**********Login Grace time has been set already!**********\n'
                logging.warning('Login Grace time has been set already')
            elif filecontent.find('#LoginGraceTime 2m') != 0:
                logging.warning('Customized value found')
            else:
                filecontent = filecontent +"\nLoginGraceTime 1m"
                flag = 1
            if flag == 1:
                fout = open(A, 'w')
                fout.write(filecontent)
                fout.close()
                print "\n**********Login Grace time has been successfully set!**********\n"
                logging.info('Login Grace time has been successfully set')
        else:
            line1 = "LoginGraceTime 1m"
            with open(A, 'a') as out:
                out.write('{}\n'.format(line1))
            print "\n**********Login Grace time has been successfully set!**********\n"
            logging.info('Login Grace time has been successfully set')
    except IOError:
        print "\nScript exited abnormally...!!!"
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)

        subprocess.call('systemctl restart sshd', shell=True)
if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_set_grace_time.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'set_grace_time.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()

    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        ssh_login()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
