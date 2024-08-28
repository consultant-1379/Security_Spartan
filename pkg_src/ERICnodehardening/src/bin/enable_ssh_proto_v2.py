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
# Name      : enable_ssh_proto_v2.py
# Purpose   : This script enables protocol 2.
# ********************************************************************
"""

import subprocess
import time
import logging
import os

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification
file_name = "/etc/ssh/ssh_config"

def ssh_protocol():
    """This function sets the OPENSSH version as version 2"""

    backup_files(file_name, [])
    with open(file_name, 'r') as fin:
        data1 = fin.read()
    with open(file_name, 'r') as fin:
        data1 = fin.read()
    data1 = data1.split('\n')
    for i in data1:
        if '#Protocol 2' in i or '#   Protocol 2' in i:
            a = data1.index(i)
            data1[a] = 'Protocol 2'
    with open(file_name, 'w') as fout:
        fout.writelines('\n'.join(data1))
    subprocess.call(" systemctl restart sshd", shell=True)
    print "\n**********Enforced SSH Protocol v2 for SSH communication on the server**********\n"
    logging.info('Enforced SSH Protocol v2 for SSH communication on the server')

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_enable_ssh_proto_v2.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)

    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    status = subprocess.check_output("echo $?", shell=True)
    if status == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        ssh_protocol()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
