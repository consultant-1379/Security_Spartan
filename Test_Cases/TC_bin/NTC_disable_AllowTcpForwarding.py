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
# Name      : NTC_disable_AllowTcpForwarding.py
# Purpose   : This script is to check negative scenarios by
#             enabling AllowTcpForwarding.
#
#
# ******************************************************************************
"""

import os
import logging
import time
import commands as c
from TC_disable_AllowTcpForwarding import disable_TCP

def enable_TCP():

    AllowTcpForwarding()

    status = disable_TCP()
    os.system("/ericsson/security/bin/disable_AllowTcpForwarding.py > /dev/null 2>&1")
    if status == "FAIL":
        return "SUCCESS"
    else:
        return "FAIL"


def AllowTcpForwarding():
    """This function enables TcpForwarding in sshd_config file"""
    flag = 0
    fin = open('/etc/ssh/sshd_config', 'r')
    filedata = fin.read()
    fin.close()
    if filedata.find('AllowTcpForwarding no') != -1:
        filedata = filedata.replace("AllowTcpForwarding no","#AllowTcpForwarding yes")
        flag = 1
    elif filedata.find('#AllowTcpForwarding yes') != -1:
        print "\n********** AllowTcpForwarding for SSH communication on the server is \
already enabled *********\n"
        logging.info('AllowTcpForwarding is already enabled ')
    else:
        filedata = filedata +"\nAllowTcpForwarding yes"
        flag = 1
    if flag == 1:
        fout = open('/etc/ssh/sshd_config', 'w')
        fout.write(filedata)
        fout.close()
        print "\n**********Successfully enabled AllowTcpForwarding for testing negative scenario of SSH communication\
 on the server**********\n"
        logging.info('Successfully reset AllowTcpForwarding ')


if __name__ == '__main__':

    status = os.system("/ericsson/security/bin/disable_AllowTcpForwarding.py > /dev/null 2>&1")
    if status != 0:
        logging.info("/ericsson/security/bin/disable_AllowTcpForwarding.py error")
        print "FAIL"
        exit()

    print enable_TCP()
#    os.system("/ericsson/security/bin/disable_AllowTcpForwarding.py > /dev/null 2>&1")
