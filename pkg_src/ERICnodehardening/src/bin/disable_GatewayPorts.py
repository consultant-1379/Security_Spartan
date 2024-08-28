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
# Name      : disable_GatewayPorts.py
# Purpose   : This script will disable GatewayPorts from sshd_config
#             file to prevent remote port forwardings to bind to
#             non-loopback addresses.
#
# Config File: username
#
# ********************************************************************
"""
import os
import logging
import time
import subprocess

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification
file_name = "/etc/ssh/ssh_config"

def disable_gatewayports():
    """This script will disable GatewayPorts in ssh_config file"""

    backup_files(file_name, [])
    flag1 = 0
    fin = open(file_name, 'r')
    filedata = fin.read()
    fin.close()

    if filedata.find('GatewayPorts yes') != -1:
        filedata = filedata.replace("GatewayPorts yes", "GatewayPorts no")
        flag1 = 1
    elif filedata.find('GatewayPorts no') != -1:
        print "\n**********Gateway ports are already disabled*********\n"
        logging.info('Gateway ports are already disabled ')
    else:
        filedata = filedata +"\nGatewayPorts no"
        flag1 = 1

    if flag1 == 1:
        fout = open(file_name, 'w')
        fout.write(filedata)
        fout.close()
        print "\n**********Successfully disabled gateway ports**********\n"
        logging.info('Gateway ports are successfully disabled')

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_disable_GatewayPorts.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)

    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        print "\n\033[93mDisabling Gateway ports\033[00m\n"
        disable_gatewayports()
    else:
        print "Failed to verify the security settings. Execute \
/ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
