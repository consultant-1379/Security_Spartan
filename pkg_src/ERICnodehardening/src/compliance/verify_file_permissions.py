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
# Name      : verify_file_permissions.py
# Purpose   : This script verifies whether the file permissions
#             are set to strong or not
# Reason    : EQEV-85297
# Author    : Pradeep Kumar C Doddagoudar , ZDODPRA
#
#********************************************************************
"""

import subprocess
import os
import logging

def verify_permissions():
    """This script verifies if the file permissions are set to strong or not"""

    if os.path.exists('/sys/firmware/efi'):
        files_list = ["/etc/at.allow", "/etc/at.deny",
                      "/etc/cron.allow", "/etc/crontab"]
    else:
        files_list = ["/boot/grub2/grub.cfg", "/etc/at.allow",
                      "/etc/at.deny", "/etc/cron.allow", "/etc/crontab"]

    dir_list = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                "/etc/cron.weekly", "/etc/cron.monthly"]

    file_status = check_file_permission(files_list)
    dir_status = check_dir_permission(dir_list)

    if file_status and dir_status:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT: EXECUTE 'set_file_permissions.py' TO MAKE IT COMPLIANT"

def check_file_permission(files_list):
    """This is to verify file permissions"""

    suggestion = "Execute /ericsson/security/bin/set_file_permissions.py \
to set strong permissions"

    for files in files_list:
        if os.path.exists(files):
            check = subprocess.check_output("ls -l "+files+" | cut -d' ' -f 1", shell=True)
            if check != "-rw-------.\n":
                logging.error("file permissions are not strong")
                print suggestion
                return False
            else:
                logging.info("file permissions are strong")
        else:
            logging.info(files+" file is not present")

    return True

def check_dir_permission(dir_list):
    """This is to verify directory permissions"""

    suggestion = "Execute /ericsson/security/bin/set_file_permissions.py \
to set strong permissions"

    for dirs in dir_list:
        if os.path.exists(dirs):
            check = subprocess.check_output("ls -dl "+dirs+" | cut -d' ' -f 1", shell=True)
            if check != "drwx------.\n":
                logging.error("directory permissions are not strong")
                print suggestion
                return False
            else:
                logging.info("directory permissions are strong")
        else:
            logging.info(dirs+" directory is not present")

    return True

if __name__ == '__main__':
    verify_permissions()
