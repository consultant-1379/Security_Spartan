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
# Name      : mask_alt_ctrl_del.py
# Purpose   :This script disables the unexpected and unwanted reboot
#                of server caused by pressing Ctrl+Alt+Del
# ********************************************************************
"""
import os
import time
import logging
import subprocess

from Verify_NH_Config import configure_nh
from user_verification import user_verification

def ctrl_del():
    """This function disables the unexpected reboot of server caused by pressing Ctrl+Alt+Del"""

    if os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES") is True:
        if os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES/mask_config") is False:
            os.system("touch /ericsson/security/BACKUP_CONFIG_FILES/mask_config")
            os.system("systemctl status ctrl-alt-del.target >> \
/ericsson/security/BACKUP_CONFIG_FILES/mask_config")
    else:
        os.system("mkdir -p /ericsson/security/BACKUP_CONFIG_FILES")
        os.system("touch /ericsson/security/BACKUP_CONFIG_FILES/mask_config")
        os.system("systemctl status ctrl-alt-del.target >> \
/ericsson/security/BACKUP_CONFIG_FILES/mask_config")

    os.system("systemctl mask ctrl-alt-del.target")
    print("\n**********'ctrl-alt-del' has been masked**********\n")
    logging.info('ctrl-alt-del has been masked')

if __name__ == "__main__":
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_mask_alt_ctrl_del.log'
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
        ctrl_del()
    else:
        print "Failed to verify the security settings. Execute \
/ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
