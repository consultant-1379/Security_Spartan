#!/usr/bin/python
"""
# ****************************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ****************************************************************************
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
#
#
# ********************************************************************
# Name       : TC_set_file_permissions.py
# Purpose    : Test file and directory permissions are strong or not.
#
# ********************************************************************
"""
import subprocess
import os
import logging
import time
import commands as c

def check_permissions():
    """This script verifies if the file permissions are set to strong or not"""

    files_list = ["/boot/grub2/grub.cfg", "/etc/at.allow",
                  "/etc/at.deny", "/etc/cron.allow", "/etc/crontab"]
    dir_list = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                "/etc/cron.weekly", "/etc/cron.monthly"]

    file_status = check_file_permission(files_list)
    dir_status = check_dir_permission(dir_list)

    if file_status and dir_status:
        return "SUCCESS"
    else:
        return "FAIL"

def check_file_permission(files_list):
    """This is to verify file permissions"""

    for files in files_list:
        if os.path.exists(files):
            check = subprocess.check_output("ls -l "+files+" | cut -d' ' -f 1", shell=True)
            if check != "-rw-------.\n":
                logging.info("file permissions are not set to strong")
                return False
            else:
                logging.info("file permissions are strong")
        else:
            logging.info(files+" file not present")

    return True

def check_dir_permission(dir_list):
    """This is to verify directory permissions"""

    suggestion = "Execute /ericsson/security/bin/set_file_permissions.py \
to set strong permissions"

    for dirs in dir_list:
        if os.path.exists(dirs):
            check = subprocess.check_output("ls -dl "+dirs+" | cut -d' ' -f 1", shell=True)
            if check != "drwx------.\n":
                logging.info("directory permissions are not strong")
                print suggestion
                return False
            else:
                logging.info("directory permissions are set to strong")
        else:
            logging.info(dirs+" directory not present")

    return True

#if __name__ == '__main__':
#    verify_permissions()


if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_file_permissions.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/set_file_permissions.py > /dev/null 2>&1")
    if status != 0:
        logging.info("/ericsson/security/bin/set_file_permissions.py error")
        print  "FAIL"
        exit()


    print check_permissions()
