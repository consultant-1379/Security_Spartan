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
# Name      : configure_icmp.py
# Purpose   : This script configures the ICMP with required iptable rules.
# ********************************************************************
"""

import os
import subprocess
import commands
import logging
import time

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification

def block_icmp_type(str):
    """This function blocks the icmp types listed"""
    block_status = commands.getoutput("firewall-cmd --add-icmp-block=%s" % str)
    if block_status == 'success':
        return 'yes'
    else:
        return 'no'

def icmp_configure():
    """This function blocks the icmp types: redirect, router-solicitation, \
timestamp-reply and router-advertisement"""

    active_status = subprocess.check_output("systemctl status firewalld | grep -i Active | \
cut -d':' -f 2 | cut -d ' ' -f 2", shell=True)
    enabled_status = subprocess.check_output("systemctl status firewalld | sed -n '/Loaded:/p' | \
cut -d ';' -f 2 | cut -d ' ' -f 2", shell=True)

    if active_status == "inactive\n" and enabled_status == "disabled\n":
        print "Start and enable firewalld service by executing /ericsson/security/bin/\
enable_firewall.py"
    elif active_status == "inactive\n" and enabled_status == "enabled\n":
        print "Start the firewalld service by executing /ericsson/security/bin/enable_firewall.py"
    elif active_status == "active\n" and enabled_status == "disabled\n":
        print "Activate the firewalld service by executing /ericsson/security/bin/\
enable_firewall.py"
    elif active_status == "active\n" and enabled_status == "enabled\n":
        logging.info('firewalld service is already active and enabled!')
        backup_files('/etc/sysctl.conf', [])
        if os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES") is True:
            if os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES/icmp_config") is False:
                os.system("touch /ericsson/security/BACKUP_CONFIG_FILES/icmp_config")
        else:
            os.system("mkdir -p /ericsson/security/BACKUP_CONFIG_FILES")
            os.system("touch /ericsson/security/BACKUP_CONFIG_FILES/icmp_config")

        icmp_types = ["redirect", "timestamp-reply", "router-solicitation", "router-advertisement"]

        for i in icmp_types:
            icmp_status = commands.getoutput("firewall-cmd --query-icmp-block=%s" % i)
            if icmp_status == 'yes':
                print "\n**********The icmp-type: %s is already restricted**********" % i
                logging.info("The icmp-type : %s is already restricted", i)
            else:
                os.system("echo %s >> /ericsson/security/BACKUP_CONFIG_FILES/icmp_config" % i)
                icmp_block_status = block_icmp_type(i)
                if icmp_block_status == 'yes':
                    print "\n**********Restricted the icmp-type : %s" % i, "**********\n"
                    logging.info("Restricted the icmp-type : %s", i)
                else:
                    print "Failed to restrict the icmp-type : %s", i
                    logging.error("Failed to restrict the icmp-type : %s", i)

        if 'net.ipv4.icmp_echo_ignore_all = 0' not in open('/etc/sysctl.conf').read():
            os.system("echo net.ipv4.icmp_echo_ignore_all = 0 >> /etc/sysctl.conf")

        os.system("firewall-cmd --runtime-to-permanent > /dev/null 2>&1")
        os.system("sysctl -p > /ericsson/security/bin/temp.txt")
        os.system("rm -rf /ericsson/security/bin/temp.txt")

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_configure_icmp.log'
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
        icmp_configure()
    else:
        print "Failed to verify the security settings. Execute \
/ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "\nScript logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
