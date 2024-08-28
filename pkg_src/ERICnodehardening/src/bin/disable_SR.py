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
# Name      : disable_SR.py
# Purpose   :This script disables source routing to avoid packet
#               sniffing and spoofing.
# ********************************************************************
"""
import subprocess
import os
import time
import logging
import getpass
from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from sentinel_hardening import log_func
from user_verification import user_verification

with open("/etc/sysctl.conf", 'r') as fin:
    data = fin.read()
data = data.strip()

def disable_source_customized():
    customized_parameters = ['net.ipv4.conf.all.accept_source_route=1',
        'net.ipv4.conf.default.accept_source_route=1','net.ipv6.conf.all.accept_source_route=1',
        'net.ipv6.conf.default.accept_source_route=1','net.ipv4.conf.all.accept_redirects=1',
        'net.ipv4.conf.default.accept_redirects=1','net.ipv6.conf.all.accept_redirects=1',
        'net.ipv6.conf.default.accept_redirects=1','net.ipv4.conf.all.send_redirects=1',
        'net.ipv4.conf.default.send_redirects=1']
    if any(word in data for word in customized_parameters):
        return 0

def remove_duplicate():
    lines_seen = set()
    with open("/etc/sysctl.conf", "r+") as f:
        data_1 = f.readlines()
        f.seek(0)
        for steer in data_1:
            if steer not in lines_seen:
                f.write(steer)
                lines_seen.add(steer)
        f.truncate()

def disable_source():
    """This function disables source routing"""
    backup_files('/etc/sysctl.conf', [])
    os.system("/sbin/sysctl -w net.ipv4.conf.all.accept_source_route=0 > /dev/null 2>&1")
    os.system("/sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0 > /dev/null 2>&1")
    os.system("/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0 > /dev/null 2>&1")
    os.system("/sbin/sysctl -w net.ipv4.conf.default.send_redirects=0 > /dev/null 2>&1")
    os.system("/sbin/sysctl -w net.ipv4.conf.default.accept_redirects=0 > /dev/null 2>&1")
    os.system("/sbin/sysctl -w net.ipv4.conf.default.accept_source_route=0 > /dev/null 2>&1")
    os.system("/sbin/sysctl -w net.ipv6.conf.all.accept_source_route=0 > /dev/null 2>&1")
    os.system("/sbin/sysctl -w net.ipv6.conf.default.accept_source_route=0 > /dev/null 2>&1")
    os.system("/sbin/sysctl -w net.ipv6.conf.all.accept_redirects=0 > /dev/null 2>&1")
    os.system("/sbin/sysctl -w net.ipv6.conf.default.accept_redirects=0 > /dev/null 2>&1")

    try:
        if 'net.ipv4.conf.all.send_redirects = 0' in data:
            os.system("sed -i '/net.ipv4.conf.all.send_redirects = 0/d' /etc/sysctl.conf")
        if 'net.ipv4.conf.default.send_redirects = 0' in data:
            os.system("sed -i '/net.ipv4.conf.default.send_redirects = 0/d' /etc/sysctl.conf")
        if 'net.ipv4.conf.all.accept_redirects = 0' in data:
            os.system("sed -i '/net.ipv4.conf.all.accept_redirects = 0/d' /etc/sysctl.conf")
        if 'net.ipv4.conf.default.accept_redirects = 0' in data:
            os.system("sed -i '/net.ipv4.conf.default.accept_redirects = 0/d' /etc/sysctl.conf")
        if 'net.ipv4.conf.all.accept_source_route = 0' in data:
            os.system("sed -i '/net.ipv4.conf.all.accept_source_route = 0/d' /etc/sysctl.conf")
        if 'net.ipv4.conf.default.accept_source_route = 0' in data:
            os.system("sed -i '/net.ipv4.conf.default.accept_source_route = 0/d' /etc/sysctl.conf")

        parameters = ['net.ipv4.conf.all.accept_source_route=0','net.ipv4.conf.default.accept_source_route=0',
            'net.ipv6.conf.all.accept_source_route=0','net.ipv6.conf.default.accept_source_route=0',
            'net.ipv4.conf.all.accept_redirects=0','net.ipv4.conf.default.accept_redirects=0',
            'net.ipv6.conf.all.accept_redirects=0','net.ipv6.conf.default.accept_redirects=0',
            'net.ipv4.conf.all.send_redirects=0','net.ipv4.conf.default.send_redirects=0']
        if disable_source_customized() == 0:
            logging.warning('Customized value found!')
        elif all(word in data for word in parameters):
            print "\n**********Already disabled Source Routing for packet redirects, \
IP communications and accepting source routed packets!**********\n"
            logging.info('Already disabled Source Routing for packet redirects, \
IP communications and accepting source routed packets!')
        else:
            with open('/etc/sysctl.conf', 'a+') as f:
                for items in parameters:
                    f.write('%s\n' %items)
                print "\n**********Successfully disabled Source Routing for packet redirects, \
IP communications and accepting source routed packets!**********\n"
                logging.info('Successfully disabled Source Routing for packet redirects, \
IP communications and accepting source routed packets!')
            f.close()
            remove_duplicate()

    except (IOError, StandardError):
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)
if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_disable_SR.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'disable_SR.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        disable_source()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
