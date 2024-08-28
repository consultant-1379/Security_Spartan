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
# Name     : configure_sshd.py
# Purpose : This script configures sshd by disabling Agent Forwarding
#
#
# ********************************************************************
"""
import subprocess
import os
import time
import logging

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification
file_name = "/etc/ssh/sshd_config"

#------------------------------------------------------------------------------------
#SSHD to disable agent forwarding
#------------------------------------------------------------------------------------
def agent_fwdng():
    """This function disables Agent Forwarding"""

    backup_files(file_name, [])
    with open(file_name) as fin:
        newtext = fin.read().replace('#AllowAgentForwarding yes', 'AllowAgentForwarding no')
    with open(file_name, "w") as fin:
        fin.write(newtext)
    print "\n**********Disabled Agent Forwarding for SSH communication on the server**********\n"
    logging.info('Disabled Agent Forwarding to configure SSHD')
    print "\nRestarting the SSHD service. . . . . .\n"
    logging.info('Restarting the SSHD service')
    os.system("systemctl restart sshd")

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_configure_sshd.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)

    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        agent_fwdng()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
