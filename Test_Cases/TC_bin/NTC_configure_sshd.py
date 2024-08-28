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
# ******************************************************************************
# Name      : NTC_configure_sshd.py
# Purpose   : This script is to check negative scenarios by
#             enabling agent forwarding for SSH communication.
#
#
# ******************************************************************************
"""

import os
import commands as c
import logging
import time
from TC_configure_sshd import Agent

def negative_sshd():

    if os.path.exists("/etc/ssh/sshd_config") == False:
        print "FAIL"
        logging.info("/etc/ssh/sshd_config not available")
        exit()
    check = open("/etc/ssh/sshd_config","r").read().split('\n')

    data = open('/etc/ssh/sshd_config', 'r').read().split('\n')
    for line in check:
        if line not in data and line != "#AllowAgentForwarding yes":
            print "FAIL"
            logging.info("%s not in /etc/ssh/sshd_config earlier" % line)
            exit()

    with open('/etc/ssh/sshd_config') as fin:
        newText = fin.read().replace('AllowAgentForwarding no', '#AllowAgentForwarding yes')
    with open('/etc/ssh/sshd_config', "w") as fin:
        fin.write(newText)
    print "\n**********Enabling Agent Forwarding for SSH communication on the server**********\n"
    logging.info('Enabled Agent Forwarding to SSHD')
    print "\nRestarting the SSHD service. . . . . .\n"
    logging.info('Restarting the SSHD service')
    os.system("systemctl restart sshd")

    status=Agent()    
    os.system("/ericsson/security/bin/configure_sshd.py > /dev/null 2>&1")
    if status == "FAIL":
        return "SUCCESS"
    else:
        return "FAIL"

if __name__ == '__main__':
    print negative_sshd()
