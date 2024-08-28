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
# Name      : TC_set_maxstartups.py 
# Purpose   : Test script to check sshd file is max startup 10:30:60
#
# ****************************************************************************
"""
import os
import logging
import commands as c
import time

def set_maxstartups():

    if os.path.exists("/etc/ssh/sshd_config") == False:
        logging.info("/etc/ssh/sshd_config file is not available")
        print "/etc/ssh/sshd_config file is not available"
        return "FAIL"
    data = open('/etc/ssh/sshd_config', 'r').read().split('\n')
    if ("MaxStartups 10:30:60" not in data):
        print "MaxStartups 10:30:60 is not set in /etc/ssh/sshd_config"
        logging.info("MaxStartups 10:30:60 is not set in /etc/ssh/sshd_config")
        return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_TC_set_maxstartups.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    status = os.system("/ericsson/security/bin/set_maxstartups.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/set_maxstartups.py error")
        exit()
    print set_maxstartups()
