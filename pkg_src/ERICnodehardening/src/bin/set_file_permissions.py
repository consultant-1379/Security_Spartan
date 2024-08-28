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
# Name      : set_file_permissions.py
# Purpose   : This script is to change the weak file permissions
# Reason    : EQEV-85297
# Author    : Pradeep Kumar C Doddagoudar, zdodpra
# ********************************************************************
"""
import os
import time
import logging
import subprocess as sub

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from sentinel_hardening import log_func
from user_verification import user_verification

def set_permission():
    """This function set file permission after checking existence"""

    if os.path.exists('/sys/firmware/efi'):
        files_list = ["/etc/at.allow", "/etc/at.deny",
                      "/etc/cron.allow", "/etc/crontab"]
    else:
        files_list = ["/boot/grub2/grub.cfg", "/etc/at.allow",
                      "/etc/at.deny", "/etc/cron.allow", "/etc/crontab"]

    dir_list = ["/etc/cron.d", "/etc/cron.daily",
                "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]

    if os.path.exists("/etc/cron.deny"):
        backup_files("/etc/cron.deny", [])
        os.system("rm -rf /etc/cron.deny")

    status1 = set_file_permission(files_list)
    status2 = set_dir_permission(dir_list)

    if status1 and status2:
        print"***************Successfully set the file permissions***************"
        logging.info("***************Successfully set the file permissions***************")
    else:
        print"***************Cannot set the file permissions***************"
        logging.info("***************Cannot set the file permissions***************")

def set_file_permission(files_list):
    """This function is to set the strong file permissions"""

    try:
        for files in files_list:
            if os.path.exists(files):
                os.system("chmod 600 "+files+"> /dev/null 2>&1")
                logging.info("Set strong permissions for the file "+files+" as per recommendation")
            else:
                print "\nFile "+files+" not Exists\n"
                logging.info("File "+files+" doesn't exist")
    except (Exception, KeyboardInterrupt):
        log_func(script_name, 1, LOG_PATH)
        return False
    return True

def set_dir_permission(dir_list):
    """This function is to set the strong directory permissions"""

    try:
        for dirs in dir_list:
            if os.path.exists(dirs):
                os.system("chmod 700 "+dirs+"> /dev/null 2>&1")
                logging.info("Set strong permissions for the directory "+dirs+" \
as per recommendation")
            else:
                print "\nDirectory "+dirs+" not Exists\n"
                logging.info("Directory "+dirs+" doesn't exist")
    except (Exception, KeyboardInterrupt):
        log_func(script_name, 1, LOG_PATH)
        return False
    return True

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_set_permission.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STR = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STR)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/"+FNAME
    script_name = "set_file_permissions.py"
    log_func(script_name, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = sub.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        set_permission()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(script_name, 1, LOG_PATH)
