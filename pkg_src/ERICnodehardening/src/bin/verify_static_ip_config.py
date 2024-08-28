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
# Name      : verify_static_ip_config.py
# Purpose   : This scripts is to list down the ip's which has not been
#               configured to any nic
# ********************************************************************
"""

import subprocess
import os
import time
import logging

from Verify_NH_Config import configure_nh
from user_verification import user_verification

def ip_config():
    """This function lists the ip's which are configured to any nic"""

    if os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES/INTRFC_CONFIG_FILES") is False:
        os.system("mkdir -p /ericsson/security/BACKUP_CONFIG_FILES/INTRFC_CONFIG_FILES")

    i = []
    os.system("ls /sys/class/net/ | grep -v lo | grep -v bonding_masters > \
/ericsson/security/log/system_config.log")
    with open('/ericsson/security/log/system_config.log', 'r') as fin:
        data1 = fin.readlines()
    a = "/etc/sysconfig/network-scripts/ifcfg-"
    os.system("rm -rf /ericsson/security/log/system_config.log")
    print "\n**********Verifying interface IP configuration**********"
    logging.info('Verifying interface IP configuration')

    for i in data1:
        i = i.replace('\n', '')
        k = a+i
        file_check = os.path.exists(k)
        if file_check:
            cmd = "cat %s"%(k)
            result = subprocess.check_output(cmd, shell=True)
            if "dhcp" in result:
                os.system("cp %s /ericsson/security/BACKUP_CONFIG_FILES/INTRFC_CONFIG_FILES" % k)
                result = result.replace('BOOTPROTO=dhcp', 'BOOTPROTO=static')
                with open("/ericsson/security/log/ip_config.log", "w") as fout:
                    fout.write(''.join(result))
                    cm1 = "mv /ericsson/security/log/ip_config.log %s"%(k)
                    os.system(cm1)
                logging.info('IP address has been changed from dhcp to static for interface %s', i)
            else:
                logging.info('Static IP address is already configured for interface %s', i)
        else:
            print "\n<INFO>File not exist", k
            logging.info('%s not exist' % k)
    print "\n**********Successfully verified interface IP configuration**********"
    logging.info('Successfully verified interface IP configuration')

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + 'verify_static_ip_config.log'
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
        ip_config()
    else:
        print "Failed to verify the security settings. Execute \
/ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \033[93m/ericsson/security/log/Apply_NH_Logs/\
Manual_Exec/\033[00m directory!"
