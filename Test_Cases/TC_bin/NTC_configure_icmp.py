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
# Name      : NTC_configure_icmp.py
# Purpose   : This script is to check negative scenarios by 
#             enabling ICMP types.
#
#
# ******************************************************************************
"""


import time
import logging
import os
import subprocess as s
import commands as c
from TC_configure_icmp import icmp_configure

def check_icmp_configure():

    enable_icmp()
    status=icmp_configure()
    os.system("/ericsson/security/bin/configure_icmp.py > /dev/null 2>&1")
    if status == "FAIL":
        return "SUCCESS"
    else:
        return "FAIL"

def enable_icmp_type(str):
    block_status = c.getoutput("firewall-cmd --remove-icmp-block=%s" % str)
    if block_status == 'success':
        return 'yes'
    else:
        return 'no'

def enable_icmp():
    """This function blocks the icmp types: redirect, router-solicitation, timestamp-reply and router-advertisement"""

    active_status = s.check_output("systemctl status firewalld | grep -i Active | cut -d':' -f 2 | cut -d ' ' -f 2", shell=True)
    enabled_status = s.check_output("systemctl status firewalld | sed -n '/Loaded:/p' | cut -d ';' -f 2 | cut -d ' ' -f 2", shell=True)

    if active_status == "inactive\n" and enabled_status == "disabled\n":
        print "Start and enable firewalld service by executing /ericsson/security/bin/enable_firewall.py"
    elif active_status == "inactive\n" and enabled_status == "enabled\n":
        print "Start the firewalld service by executing /ericsson/security/bin/enable_firewall.py"
    elif active_status == "active\n" and enabled_status == "disabled\n":
        print "Activate the firewalld service by executing /ericsson/security/bin/enable_firewall.py"
    elif active_status == "active\n" and enabled_status == "enabled\n":
        logging.info('firewalld service is already active and enabled!')

        icmp_types = ["redirect", "timestamp-reply", "router-solicitation", "router-advertisement"]


        for i in icmp_types:
            icmp_enable_status = c.getoutput("firewall-cmd --query-icmp-block=%s" % i)
            if icmp_enable_status == 'no':
                print "\n**********The icmp-type: %s is already enabled**********" % i
                logging.info("The icmp-type : %s is already enabled", i)
            else:
                os.system("echo %s >> /ericsson/security/BACKUP_CONFIG_FILES/icmp_config" % i)
                icmp_block_status = enable_icmp_type(i)
                print icmp_block_status
                if icmp_block_status == 'yes':
                    print "\n**********enabled icmp-type : %s" % i, "**********\n"
                    logging.info("enabled the icmp-type : %s", i)
                else:
                    print "Failed to enable the icmp-type : %s ", i
                    logging.error("Failed to enable the icmp-type : %s", i)


if __name__ == '__main__':

    print check_icmp_configure()
