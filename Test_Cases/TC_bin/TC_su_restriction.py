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
# Name      : TC_su_restriction.py
# Purpose   : Test script to check su_restriction.py restricts su command.
#
# ****************************************************************************
"""
import os
import logging
import commands as c
import time

def su_restriction():

    if os.path.exists("/etc/pam.d/su") == False:
        logging.info("/etc/pam.d/su file is not available")
        print "/etc/pam.d/su file is not available"
        return "FAIL"
    data = open('/etc/pam.d/su', 'r').read().split('\n')
    if ("auth            required        pam_wheel.so use_uid group=sugroup" not in data):
        return "FAIL"
    else:
        return "SUCCESS"

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_su_restriction.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    status = os.system("/ericsson/security/bin/su_restriction.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/su_restriction.py error")
        exit()
    print su_restriction()
