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
# Name      : NTC_su_restriction.py
# Purpose   : Test script to check TC_su_restriction.py checks su restriction.
#
# ****************************************************************************
"""
import os
import logging
import commands as c
import time
from TC_su_restriction import su_restriction

def ntc_su_restriction():
    if os.path.exists("/etc/pam.d/su") == False:
        logging.info("/etc/pam.d/su not available")
        print "/etc/pam.d/su not available"
        return "FAIL"
    os.system("touch copyconf.txt")
    os.system("cp /etc/pam.d/su  copyconf.txt")
    data = open('/etc/pam.d/su', 'r').read().split('\n')
    newline = ''
    with open("/etc/pam.d/su") as fin:
        if ("auth            required        pam_wheel.so use_uid group=sugroup" in data):
            newline = fin.read().replace('auth            required        pam_wheel.so use_uid group=sugroup', '#auth            required        pam_wheel.so use_uid group=sugroup')
        else:
            os.system("auth            required        pam_wheel.so use_uid group=sugroup >> /etc/pam.d/su")
    if newline:
        with open("/etc/pam.d/su", "w") as fout:
            fout.write(newline)
    status=su_restriction()
    os.system("cp copyconf.txt /etc/pam.d/su")
    os.system("rm -rf copyconf.txt")
    if status == 'SUCCESS':
       return "FAIL"
    else:
       return "SUCCESS"
if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_NTC_su_restriction.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    print ntc_su_restriction()
