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
# Name      : TC_set_path_integrity.py
# Purpose   : Test script to check set_path_integrity.py ensures root 
#             PATH integrity.
#
# ****************************************************************************
"""
import os
import logging
import commands as c
import time

def set_path_integrity():

    if os.path.isfile("/root/.bash_profile") == False:
        logging.info("/root/.bash_profile file is not available")
        print "/root/.bash_profile file is not available"
        return "FAIL"
    data = open('/root/.bash_profile', 'r').read().split('\n')
    if ("#PATH=$PATH:$HOME/bin" not in data):
        return "FAIL"
    else:
        return "SUCCESS"

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_path_integrity.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    status = os.system("/ericsson/security/bin/set_path_integrity.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/set_path_integrity.py error")
        exit()
    print set_path_integrity()
