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
# ********************************************************************
# Name      : sshd_service_restart.py
# Purpose   : This script restarts sshd service.
# ********************************************************************
"""

import os
import time
import logging
import subprocess

from Verify_NH_Config import configure_nh

def sshd_restart():
    """This function restarts sshd service on the server"""
    print "\nRestarting SSHD service\n"
    logging.info('SSHD service is being restarted')
    status = os.system("systemctl restart sshd.service >> /dev/null")
    if status == 0:
        print "\nSuccessfully Restarted SSHD service\n"
        logging.info('SSHD service is restarted')
    else:
        print "\nFailed to restart SSHD service\n"
        logging.info('Failed to restart SSHD service')

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_sshd_restart.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)
    sshd_restart()
