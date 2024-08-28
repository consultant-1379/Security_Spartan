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
# Name      : NTC_disable_GatewayPorts.py
# Purpose   : This script is to check negative scenarios by
#             enabling gateway ports.
#
#
# ******************************************************************************
"""

import os
import logging
import time
import commands as c
from TC_disable_GatewayPorts import disable_Gateway

def enable_Gateway():
  
    enable_GatewayPorts()
    status = disable_Gateway()
    os.system("/ericsson/security/bin/disable_GatewayPorts.py > /dev/null 2>&1")
    if status == "FAIL":
        return "SUCCESS"
    else:
        return "FAIL"

def enable_GatewayPorts():
    """This script will disable GatewayPorts in ssh_config file"""

    flag1 = 0
    fin = open('/etc/ssh/ssh_config', 'r')
    filedata = fin.read()
    fin.close()

    if filedata.find('GatewayPorts no') != -1:
        filedata = filedata.replace("GatewayPorts no", "GatewayPorts yes")
        flag1 = 1
    elif filedata.find('GatewayPorts yes') != -1:
        print "\n**********Gateway ports are already enabled*********\n"
        logging.info('Gateway ports are already enabled ')
    else:
        filedata = filedata +"\nGatewayPorts yes"
        flag1 = 1

    if flag1 == 1:
        fout = open('/etc/ssh/ssh_config', 'w')
        fout.write(filedata)
        fout.close()
        print "\n**********Successfully enabled gateway ports**********\n"
        logging.info('Gateway ports are successfully enabled')


if __name__ == '__main__':

    print enable_Gateway()


