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
# Name      : TC_disable_ssh_emptypasswords.py 
# Purpose   : Test script to check whether SSH permit empty passwords is disabled or not.
#
# ****************************************************************************
"""
import os
import time
import logging
import commands as c

def disable_ssh_emptypasswords():

    if os.path.exists("/etc/ssh/sshd_config") == False:
        logging.info("/etc/ssh/sshd_config file is not available")
        print "/etc/ssh/sshd_config file is not available"
        return "FAIL"

    data = open('/etc/ssh/sshd_config', 'r').read().split('\n')

    if ("PermitEmptyPasswords no" not in data):
        print "PermitEmptyPasswords no is not set in /etc/ssh/sshd_config"
        logging.info("PermitEmptyPasswords no is not set in /etc/ssh/sshd_config")
        return "FAIL"
    elif("PermitEmptyPasswords yes" in data):
        print "PermitEmptyPasswords no is not set in /etc/ssh/sshd_config"
        logging.info("PermitEmptyPasswords no is not set in /etc/ssh/sshd_config")
        return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_TC_disable_ssh_emptypasswords.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    status = os.system("/ericsson/security/bin/disable_ssh_emptypasswords.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/disable_ssh_emptypasswords.py error")
        exit()
    print disable_ssh_emptypasswords()
