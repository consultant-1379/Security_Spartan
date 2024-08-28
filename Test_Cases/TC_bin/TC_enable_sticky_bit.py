#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
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
# ********************************************************************
# Name      : TC_enable_sticky_bit.py
# Purpose   : Test Case to check Sticky bit of /etc
#
# ********************************************************************
"""

import os
import commands as c
import time
import logging

def sticky():
    
    if os.path.exists('/etc/') == False :
	    print "/etc not exists"
	    logging.info("%s not exists" % file)
	    return "FAIL"

    cmd = "ls -ld /etc | head -n 1 | cut -d'.' -f1"
    check = c.getoutput(cmd)[-1].lower()
    if check != 't':
 	print "/etc has no sticky bit"
	logging.info("/etc has no sticky bit")
	return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_enable_sticky_bit.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/enable_sticky_bit.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/enable_sticky_bit.py error")
        print "FAIL"
        exit()

    print sticky()
