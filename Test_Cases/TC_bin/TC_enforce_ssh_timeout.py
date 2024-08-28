#!/usr/bin/python
"""
# ****************************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ****************************************************************************
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
# ****************************************************************************
# Name      : TC_enforce_ssh_timeout.py
# Purpcse   : Test script to check whether enforce_ssh_timeout.py sets SSH Idle
#             Timeout Interval by configuring ClientAliveCountMax and
#             ClientAliveInterval.
#
# ****************************************************************************
"""
import os
import logging
import commands as c
import time

def enforce_ssh_timeout():

    if os.path.exists("/etc/ssh/sshd_config") == False:
        logging.info("/etc/ssh/sshd_config file is not available")
        print "/etc/ssh/sshd_config file is not available"
        return "FAIL"

    data = open('/etc/ssh/sshd_config', 'r').read().split('\n')

    if ("ClientAliveInterval 900" not in data):
        print "ClientAliveInterval 900 is not set in /etc/ssh/sshd_config"
        logging.info("ClientAliveInterval 900 is not set in /etc/ssh/sshd_config")
        return "FAIL"
    if ("ClientAliveCountMax 0" not in data):
        print "ClientAliveCountMax 0 is not set in /etc/ssh/sshd_config"
        logging.info("ClientAliveCountMax 0 is not set in /etc/ssh/sshd_config")
        return "FAIL"
    return "SUCCESS"

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_TC_enforce_ssh_timeout.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    status = os.system("/ericsson/security/bin/enforce_ssh_timeout.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/enforce_ssh_timeout.py error")
        exit()
    print enforce_ssh_timeout()
