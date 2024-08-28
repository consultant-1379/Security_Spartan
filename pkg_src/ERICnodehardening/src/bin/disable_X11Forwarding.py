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
# Name      : disable_X11Forwarding.py
# Purpose   : This script will disable the X11Forwarding
#             from sshd_config file
#
# Config File: username
#
# ********************************************************************
"""

import os
import logging
import time
import subprocess

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification
file_name = "/etc/ssh/sshd_config"

def x11_forwarding():
    """This function disables X11Forwarding in sshd_config file"""

    backup_files(file_name, [])
    fin = open(file_name, 'r')
    filedata = fin.read()
    fin.close()

    newdata = filedata.replace("X11Forwarding yes", "X11Forwarding no")

    fout = open(file_name, 'w')
    fout.write(newdata)
    fout.close()
    print "\n**********Successfully disabled X11Forwarding for SSH communication on the\
 server**********\n"
    logging.info('Successfully set X11Forwarding to "no"')

if __name__ == "__main__":
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_disable_x11_forwording.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)

    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    status = subprocess.check_output("echo $?", shell=True)
    if status == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        x11_forwarding()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
