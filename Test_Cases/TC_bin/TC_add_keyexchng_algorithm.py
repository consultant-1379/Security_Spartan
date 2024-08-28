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
# Name      : TC_add_keyexchng_algorithm.py
# Purpcse   : Test script to check whether add_keyexchng_algorithm.py
#             enforces the Strong key Exchange algorithms.
#
# ****************************************************************************
"""
import os
import logging
import commands as c
import time

def add_keyexchng_algorithm():

    if os.path.exists("/etc/ssh/sshd_config") == False:
        logging.info("/etc/ssh/sshd_config file is not available")
        print "/etc/ssh/sshd_config file is not available"
        return "FAIL"

    data = open('/etc/ssh/sshd_config', 'r').read().split('\n')

    if "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" not in data:
        print "KexAlgorithms is not set in /etc/ssh/sshd_config"
        logging.info("KexAlgorithms is not set in /etc/ssh/sshd_config")
        return "FAIL"
    return "SUCCESS"

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_TC_add_keyexchng_algorithm.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    status = os.system("/ericsson/security/bin/add_keyexchng_algorithm.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/add_keyexchng_algorithm.py error")
        exit()
    print add_keyexchng_algorithm()
