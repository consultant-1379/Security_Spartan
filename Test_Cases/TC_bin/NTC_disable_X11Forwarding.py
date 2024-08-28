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
# Name      : NTC_disable_X11Forwarding.py
# Purpose   : This script is to check negative scenarios by
#             enabling X11 forwarding sshd_config file.
#
#
# ******************************************************************************
"""

import os
import time
import logging
import commands as c
from TC_disable_X11Forwarding import disable_X11

def enable_X11():

    X11Forwarding()
    status = disable_X11()
    os.system("/ericsson/security/bin/disable_X11Forwarding.py > /dev/null 2>&1")
    if status == "FAIL":
        return "SUCCESS"
    else:
        return "FAIL"

def X11Forwarding():
    """This function enables X11Forwarding in sshd_config file"""

    fin = open('/etc/ssh/sshd_config', 'r')
    filedata = fin.read()
    fin.close()

    newdata = filedata.replace("X11Forwarding no", "X11Forwarding yes")

    fout = open('/etc/ssh/sshd_config', 'w')
    fout.write(newdata)
    fout.close()
    print "\n**********Successfully enabled X11Forwarding for SSH communication on the\
 server**********\n"
    logging.info('Successfully reset X11Forwarding to "yes"')

if __name__ == '__main__':

    print enable_X11()
    os.system("/ericsson/security/bin/disable_X11Forwarding.py > /dev/null 2>&1")
