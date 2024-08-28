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
# Name      : NTC_enable_sshHostKey_verification.py
# Purpose   : This script is to check negative scenarios by
#             setting VerifyHostKeyDNS and StrictHostKeyChecking parameters to yes.
#
# ******************************************************************************
"""

import os
import logging
import commands as c
import time
from TC_enable_sshHostKey_verification import enable_sshHostKey

def disable_sshHostKey():

    sshHostKey()
    status = enable_sshHostKey()
    os.system("/ericsson/security/bin/enable_sshHostKey_verification.py > /dev/null 2>&1")
    if status == "FAIL":
        return "SUCCESS"
    else:
        return "FAIL"

def sshHostKey():
    """This script verify ssh host key permission in ssh_config file"""

    flag1 = 0
    flag2 = 0
    fin = open('/etc/ssh/ssh_config', 'r')
    filedata = fin.read()
    fin.close()

    if filedata.find('Verifyhostkeydns ask') != -1:
        filedata = filedata.replace("Verifyhostkeydns ask","Verifyhostkeydns yes")
        flag1 = 1
    elif filedata.find('Verifyhostkeydns yes') != -1 or filedata.find('Verifyhostkeydns no') != -1:
        pass
    else:
        filedata = filedata +"\nVerifyhostkeydns yes"
        flag1 = 1

    if filedata.find('stricthostkeychecking ask') != -1:
        filedata = filedata.replace("stricthostkeychecking ask","stricthostkeychecking yes")
        flag2 = 1
    elif filedata.find('stricthostkeychecking yes') != -1 or filedata.find('stricthostkeychecking no') != -1 :
        pass
    else:
        filedata = filedata +"\nstricthostkeychecking yes"
        flag2 = 1
    if flag1 == 1 or flag2 == 1:
        f = open('/etc/ssh/ssh_config', 'w')
        f.write(filedata)
        f.close()
        print "\n**********Successfully disabled ssh host and key dns verification**********\n"
        logging.info('Successfully disabled ssh host and key dns verification')
    else:
        print "\n*********ssh host and key verification is already disbled on the server*********\n"
        logging.info('ssh host and key verification is already disabled on the server')



if __name__ == '__main__':

    print disable_sshHostKey()

