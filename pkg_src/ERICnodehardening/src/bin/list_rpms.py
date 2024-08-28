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
# Name      : list_rpms.py
# Purpose   : This script lists the installed rpm packages and saves in the directory:
#               /ericsson/security/log/rpm_logs/<date>_rpm_list
# ********************************************************************
"""

import logging
import subprocess
import os
import time

from Verify_NH_Config import configure_nh
from user_verification import user_verification

timestr = time.strftime("%Y%m%d-%H%M%S")

#--------------------------------------------------------------------------------------
#rpm check
#--------------------------------------------------------------------------------------
def check_rpms():
    """This function lists all the installed rpms and saves it under:\
 /ericsson/security/log/rpm_logs/ directory"""
    filename = timestr + '_rpm_list'
    os.system("mkdir -p /ericsson/security/log/rpm_logs")

    file_ = open('/ericsson/security/log/rpm_logs/%s' % filename, "w")
    subprocess.call(['rpm', '-qa'], stdout=file_)
    print "\n*********All the installed rpm files are listed and logged \
in /ericsson/security/log/rpm_logs/%s" % filename, "*********\n"
    logging.info('All the installed rpm files are listed and \
logged in /ericsson/security/log/rpm_logs')

if __name__ == '__main__':
    user_verification()
    fname = timestr + '_list_rpms.log'
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
        check_rpms()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
