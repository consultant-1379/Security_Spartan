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
# Name      : NTC_set_maxstartups
# Purpose   : Test script to check sshd file is having the parameter 
#             MaxStartups 10:30:60
#
# ****************************************************************************
"""
import os
import logging
import commands as c
import time
from TC_set_maxstartups import set_maxstartups

def ntc_set_maxstartups():
    if os.path.exists("/etc/ssh/sshd_config") == False:
        logging.info("/etc/ssh/sshd_config not available")
        print "/etc/ssh/sshd_config not available"
        return "FAIL"
    os.system("touch copyconf.txt")
    os.system("cp /etc/ssh/sshd_config  copyconf.txt")
    data = open('/etc/ssh/sshd_config', 'r').read().split('\n')
    newline = ''
    with open("/etc/ssh/sshd_config") as fin:
        if ("MaxStartups 10:30:60" in data):
            newline = fin.read().replace('MaxStartups 10:30:60', 'MaxStartups 10:30:100')
        else:
            os.system("MaxStartups 10:30:100 >> /etc/ssh/sshd_config")
    if newline:
        with open("/etc/ssh/sshd_config", "w") as fout:
            fout.write(newline)
    status=set_maxstartups()
    os.system("cp copyconf.txt /etc/ssh/sshd_config")
    os.system("rm -rf copyconf.txt")
    if status == 'SUCCESS':
       return "FAIL"
    else:
       return "SUCCESS"
if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_NTC_set_maxstartups.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    print ntc_set_maxstartups()
