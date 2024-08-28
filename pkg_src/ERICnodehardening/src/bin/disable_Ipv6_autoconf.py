#!/usr/bin/python
"""
# **************************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ***************************************************************************
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
# *****************************************************************************
# Name      : disable_Ipv6_autoconf.py
# Purpose   : This script will disable Ipv6 autoconf feature.
#
# ******************************************************************************
"""
import os
import logging
import time
import subprocess
import os.path

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification
file_name = "/etc/sysctl.conf"

def disable_ipv6_autoconf():
    """This script disables Ipv6 autoconf feature"""

    backup_files(file_name, [])
    flag = 0
    if os.path.exists(file_name):
        sysctlfile = open(file_name, 'r')
        sysctl = sysctlfile.read()
        sysctlfile.close()
        if sysctl.find('net.ipv6.conf.default.autoconf=1') != -1:
            sysctl = sysctl.replace("net.ipv6.conf.default.autoconf=1",\
 "net.ipv6.conf.default.autoconf=0")
            flag = 1
        elif sysctl.find('net.ipv6.conf.default.autoconf=0') != -1:
            print "\n********** ipv6 autoconf feature is already disabled *********\n"
            logging.info('ipv6 autoconf feature is already disabled ')
        else:
            sysctl = sysctl +"net.ipv6.conf.default.autoconf=0\n"
            flag = 1
        if flag == 1:
            fout = open(file_name, 'w')
            fout.write(sysctl)
            fout.close()
            print "\n**********Successfully disabled ipv6 autoconf feature**********\n"
            logging.info('Successfully set net.ipv6.conf.default.autoconf as "0"')
    else:
        print "/etc/sysctl.conf file does not exist"

if __name__ == "__main__":
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_disable_Ipv6_autoconf.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec")

    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)

    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    status = subprocess.check_output("echo $?", shell=True)
    if status == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        disable_ipv6_autoconf()
    else:
        print "Failed to verify the security settings. Execute \
/ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
