#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
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
# *********************************************************************
# Name      : remove_kex_algos.py
# Purpose   : This script removes the enforced SSH Strong key Exchange
#             algorithms on Gen9 server.
#
# *********************************************************************
"""
import subprocess
import time
import logging
import os
import getpass
import commands

from user_verification import user_verification

def check_hwtype():
    """This function removes the enforced SSH Key Exchange Algorithms on Gen9 server and \
its client."""

    try:
        print"*********Checking the hardware type of server*********"
        logging.info('*********Checking the hardware type of server*********')
        cmd = "dmidecode -t system | grep -i product | cut -d' ' -f 5"
        type_of_server = commands.getoutput(cmd)
        if type_of_server == 'Gen10':
            print"Strong Key Exchange algorithms are supported for Gen10 server"
            logging.info('Strong Key Exchange algorithms are supported for Gen10 server')
        else:
            kex_algorithms = 'KexAlgorithms curve25519\\-sha256\\,curve25519\\-sha256\\@libssh' \
                             '\\.org\\,diffie\\-hellman\\-group14\\-sha256\\,diffie\\-hellman' \
                             '\\-group16\\-sha512\\,diffie\\-hellman\\-group18\\-sha512\\,ecdh' \
                             '\\-sha2\\-nistp521\\,ecdh\\-sha2\\-nistp384\\,ecdh\\-sha2' \
                             '\\-nistp256\\,diffie\\-hellman\\-group\\-exchange\\-sha256'

            cmd_remove_ssh_config = "sed -i -e '/" + kex_algorithms + "/d' /etc/ssh/ssh_config"
            cmd_remove_sshd_config = "sed -i -e '/" + kex_algorithms + "/d' /etc/ssh/sshd_config"
            os.system(cmd_remove_ssh_config)
            os.system(cmd_remove_sshd_config)
            print"\n********Removed the Strong Kex algorithms enforced as part of Node \
Hardening********\n"
            logging.info("Removed the Strong Kex algorithms enforced as part of Node Hardening")
            logging.info('Restarting the SSHD service')
            os.system("systemctl restart sshd")
    except (IOError, ValueError):
        logging.error('Script exited abnormally')

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + 'remove_keyexchng_algorithm.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    check_hwtype()
    print"Script logs are saved at : "+LOG_PATH

