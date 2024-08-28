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
# Name      : TC_set_maxauthtries.py
# Purpose   : Test script to check sshd file is having maxauthtries to 4
#
# ****************************************************************************
"""
import os
import logging
import commands as c
import time
from TC_set_maxauthtries import set_maxauthtries

def maxauthtries():
    if os.path.exists("/etc/ssh/sshd_config") == False:
        logging.info("/etc/ssh/sshd_config not available")
        print "/etc/ssh/sshd_config not available"
        return "FAIL"
    os.system("touch copyconf.txt")
    os.system("cp /etc/ssh/sshd_config  copyconf.txt")
    data = open('/etc/ssh/sshd_config', 'r').read().split('\n')
    newline = ''
    with open("/etc/ssh/sshd_config") as fin:
        if ("MaxAuthTries 4" in data):
            newline = fin.read().replace('MaxAuthTries 4', 'MaxAuthTries 6')
        elif ("#MaxAuthTries 6" in data):
            newline = fin.read().replace('#MaxAuthTries 6', 'MaxAuthTries 6')
        else:
            os.system("MaxAuthTries 6 >> /etc/ssh/sshd_config")
    if newline:
        with open("/etc/ssh/sshd_config", "w") as fout:
            fout.write(newline)
    status=set_maxauthtries()
    os.system("cp copyconf.txt /etc/ssh/sshd_config")
    os.system("rm -rf copyconf.txt")
    if status == 'SUCCESS':
       return "FAIL"
    else:
       return "SUCCESS"
if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_NTC_set_maxauthtries.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    print maxauthtries()
