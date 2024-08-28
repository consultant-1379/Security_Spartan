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
# Name      : reboot.py
# Purpose   : This script reboots the server. Execute this after all
#             the node hardening procedures are successfully applied.
# ********************************************************************
"""
import os
import time
import logging
import subprocess

from Verify_NH_Config import configure_nh

def reboot():
    """This function reboots the server"""
    os.system("mkdir -p /ericsson/security/compliance/Reports")
    print "\nThe server will reboot now. . .\n"
    logging.warning('The server will reboot now')
    os.system("sleep 3s")
    os.system("init 6")

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_reboot.log'
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
        reboot()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
