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
# Name      : enable_firewall.py
# Purpose   : This script enables the firewalld service.
# ********************************************************************
"""

import os
import subprocess
import time
import logging

from user_verification import user_verification

systemctl_cmd = "systemctl enable firewalld > /dev/null 2>&1"
log_inf = "Reloading firewalld service"
firewall_cmd = "firewall-cmd --reload > /dev/null 2>&1"

def firewall():
    """This function enables firewalld service"""
    active_status = subprocess.check_output("systemctl status firewalld | grep -i Active | \
cut -d':' -f 2 | cut -d ' ' -f 2", shell=True)
    enabled_status = subprocess.check_output("systemctl status firewalld | sed -n '/Loaded:/p' | \
cut -d ';' -f 2 | cut -d ' ' -f 2", shell=True)

    if active_status == "inactive\n" and enabled_status == "disabled\n":
        os.system("systemctl start firewalld")
        os.system(systemctl_cmd)
        logging.info(log_inf)
        os.system(firewall_cmd)
        print "\n**********Successfully started and enabled firewalld service**********\n"
        logging.info('Successfully started and enabled firewalld service')
#        open_nw_ports()
    elif active_status == "inactive\n" and enabled_status == "enabled\n":
        os.system("systemctl start firewalld")
        os.system(systemctl_cmd)
        logging.info(log_inf)
        os.system(firewall_cmd)
        print "\n**********Successfully started firewalld service**********\n"
        logging.info('Successfully started firewalld service')
#        open_nw_ports()
    elif active_status == "active\n" and enabled_status == "disabled\n":
        os.system("systemctl restart firewalld")
        os.system(systemctl_cmd)
        logging.info(log_inf)
        os.system(firewall_cmd)
        print "\n**********Successfully enabled firewalld service**********\n"
        logging.info('Successfully enabled firewalld service')
#        open_nw_ports()
    elif active_status == "active\n" and enabled_status == "enabled\n":
        print "\n**********firewalld service is already active and enabled!**********\n"
        logging.info('firewalld service is already active and enabled')
        if os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES") is True:
            if os.path.exists("/ericsson/security/BACKUP_CONFIG_FILES/open_ports_config") is False:
                os.system("touch /ericsson/security/BACKUP_CONFIG_FILES/open_ports_config")
                os.system("firewall-cmd --list-ports >> /ericsson/security/BACKUP_CONFIG_FILES/\
open_ports_config")
        else:
            os.system("mkdir -p /ericsson/security/BACKUP_CONFIG_FILES")
            os.system("touch /ericsson/security/BACKUP_CONFIG_FILES/open_ports_config")
            os.system("firewall-cmd --list-ports >> /ericsson/security/BACKUP_CONFIG_FILES/\
open_ports_config")
#        open_nw_ports()
# The functionality of the below function has been implemented using Verify_NH_config.py script

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_enable_firewall.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)

    firewall()
    #else:
    #    print "Failed to verify the security settings. \
#Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
