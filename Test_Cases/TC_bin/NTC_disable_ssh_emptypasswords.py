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
#
# ****************************************************************************
# Name      : NTC_disable_ssh_emptypasswords.py 
# Purpose   : Test script to check whether SSH permit empty passwords is disabled or not.
#
# ****************************************************************************
"""
import os
import time
import logging
import commands as c
from TC_disable_ssh_emptypasswords import disable_ssh_emptypasswords

def ssh_emptypasswords():

    if os.path.exists("/etc/ssh/sshd_config") == False:
        logging.info("/etc/ssh/sshd_config file is not available")
        print "/etc/ssh/sshd_config file is not available"
        return "FAIL"

    os.system("touch copyconf.txt")
    os.system("cp /etc/ssh/sshd_config copyconf.txt")

    data = open('/etc/ssh/sshd_config', 'r').read().split('\n')
    newline = ''

    with open("/etc/ssh/sshd_config") as fin:
        if ("PermitEmptyPasswords no" in data):
            newline = fin.read().replace('PermitEmptyPasswords no', 'PermitEmptyPasswords yes')
        else:
            os.system("echo PermitEmptyPasswords yes >> /etc/ssh/sshd_config")

    if newline:
        with open("/etc/ssh/sshd_config", "w") as fout:
            fout.write(newline)

    status=disable_ssh_emptypasswords()

    os.system("cp copyconf.txt /etc/ssh/sshd_config")
    os.system("rm -rf copyconf.txt")

    if status == 'SUCCESS':
       return "FAIL"
    else:
       return "SUCCESS"

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_NTC_disable_ssh_emptypasswords.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    print ssh_emptypasswords()
