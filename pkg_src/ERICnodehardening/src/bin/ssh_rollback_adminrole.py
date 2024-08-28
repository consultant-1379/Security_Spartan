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
# *********************************************************************
# Name     : ssh_rollback_adminrole.py
# Purpose  : This script reverts back ssh access for Admin Users.
# Author   : ZBARPHU
# Revision : A
# Reason   : EQEV-106690
# *********************************************************************
"""
import os
import subprocess
import time
import logging
from enable_ssh_login import ssh_user
from sentinel_hardening import log_func
try:
    def logging_function():
        TIMESTR = time.strftime("%Y%m%d-%H%M%S")
        FNAME = TIMESTR + '_ssh_rollback_adminrole.log'
        os.system("mkdir -p /ericsson/security/log/admin_role_log/")
        FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
        logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/admin_role_log/%s" % FNAME,
                        format=FORMAT_STRING)
        LOG_PATH = "/ericsson/security/log/admin_role_log/%s" % FNAME
        SCRIPT_NAME = 'ssh_rollback_adminrole.py'
        log_func(SCRIPT_NAME, 0, LOG_PATH)
    def group_existence_check():
        """This function verifies whether the ENIQ_ADMIN_ROLE group is present or not"""
        logging_function()
        group_existence = subprocess.check_output("cat /etc/group | grep ENIQ_ADMIN_ROLE | \
cut -d':' -f 1", shell=True).strip()
        if group_existence != "ENIQ_ADMIN_ROLE":
            logging.warning('Privileged user group is not present on the server. \
Script execution exited!')
            return 0
    def rollback_ssh_eniq_admin_role():
        logging_function()
        if group_existence_check() == 0:
            return 0
        with open("/etc/ssh/sshd_config", 'r') as fin:
            data = fin.read()
        data = data.split()
        if 'AllowUsers' not in data:
            logging.warning('SSH access parameter is not configured in config file. Script \
execution exited!')
            return 0
        else:
            with open("/etc/ssh/sshd_config", 'r+') as file:
                lines = file.readlines()
            with open("/etc/ssh/sshd_config", 'w') as file:
                for line in lines:
                    line1 = line.strip("\n")
                    if line1.find('AllowUsers') == -1:
                        file.write(line)
            file.close()
            os.system("/ericsson/security/bin/enable_ssh_login.py --skipug >> /dev/null")
            logging.info('Successfully Rolled back the SSH access for Privileged Users!')
            return 1
except IOError:
    print "Script exited abnormally!"
    logging.warning('Script exited abnormally!')
if __name__ == '__main__':
    rollback_ssh_eniq_admin_role()
