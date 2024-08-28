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
# Name      : set_motd_banner.py
# Purpose   : Displays an MOTD(Message of the day) banner message.
#
#
#Config File: banner_motd
# ********************************************************************
"""

import os
import time
import logging
import filecmp
import subprocess

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification
file_name = "/etc/motd"

def motd():
    """This function sets an MOTD banner message"""

    backup_files(file_name, [])
    with open('/ericsson/security/bin/banner_motd', 'r') as fin:
        data = fin.read()
    logging.info('\n'+data)

    comp = filecmp.cmp("/ericsson/security/bin/banner_motd", file_name)

    if os.stat(file_name).st_size == 0:
        with open(file_name, 'w') as fout:
            fout.write(data)
        print "\n**********Successfully configured MOTD Banner on the server!*********\n"
        logging.info('Successfully configured MOTD Banner on the server!')
    elif comp:
        print "\n**********MOTD BANNER is already configured on the server!*********\n"
        logging.info('MOTD BANNER is already configured on the server!')
    elif not comp:
        if os.stat(file_name).st_size == 744:
            with open(file_name, 'w') as fout:
                fout.write(data)
            print "\n**********Successfully updated MOTD Banner on the server!*********\n"
            logging.info('Successfully updated MOTD Banner on the server!')
        else:
            logging.info('Customized banner message found!\n')
            with open(file_name, 'r') as fin:
                data1 = fin.read()
            logging.info('\n'+data1)
            fin.close()

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_motd_banner.log'
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
        motd()
    else:
        print "Failed to verify the security settings. Execute \
/ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
