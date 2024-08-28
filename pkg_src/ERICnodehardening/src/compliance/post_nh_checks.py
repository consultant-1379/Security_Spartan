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
# Name      : post_nh_Checks.py
# Purpose   : This script checks and logs the status of the server after Node hardening.
#
# ********************************************************************
"""

import os
import logging
import time
import sys

sys.path.insert(0, '/ericsson/security/bin')
from pre_nh_checks import Precheck

def start_post_check():
    """"Function to start post node hardening check"""
    POST_FILE = '/ericsson/security/log/Apply_NH_Logs/post_check_data.log'
    post_check = Precheck(POST_FILE)
    COLORS = {'RED' : '\33[31m', 'END' : '\033[0m', 'GREEN' : '\33[32m',
              'YELLOW' : '\33[33m', 'BLUE':'\33[94m'}
    services = {'sshd':('active', 'enabled'), 'nfs':('active', 'enabled'),
                'crond':('active', 'enabled'), 'auditd':('active', 'enabled'),
                'rsyslog':('active', 'enabled'), 'named':('active', 'enabled'),
                'rpcbind':('active', 'enabled'), 'kdump':('active', 'enabled'),
                'ntpd':('inactive', 'disabled'),}
    server_deployment = post_check.find_deployment()
    logging.info('Captured Server Deployment')
    server_type = post_check.find_type()
    logging.info('Captured Server Hardware Type')
    l_volume, mnt = post_check.find_lvs()
    logging.info('Captured Server LV, VG, Mounted FS')
    boot_error = post_check.check_fs()
    logging.info('Captured the status of File Systems')
    firewall, port, service, icmp, rich_rules = post_check.firewall_details(['active', 'enabled'])
    logging.info('Captured Server Firewall details')
    tmout, xterm_var = post_check.find_var('900')
    logging.info('Captured Server Time out and Term variable')
    service_s = post_check.find_service_status(services)
    logging.info('Captured Services status')
    with open(POST_FILE, 'a') as pf:
        timestr = time.strftime("%Y%m%d-%H%M%S")
        pf.write('{}\n'.format(timestr))
        pf.write('{}Warnings Found : {}{}\n'.format(COLORS['YELLOW'], \
post_check.WAR, COLORS['END']))
        pf.write('\n'+'*'*20+'\nSERVER INFORMATION\n'+'*'*20+'\n')
        pf.write('{}Server Config :{} {}\n'.format(COLORS['BLUE'], COLORS['END'], \
server_deployment))
        pf.write('{}Server Type :{} {}\n'.format(COLORS['BLUE'], COLORS['END'], server_type))
        pf.write('\n'+'*'*20+'\nFIREWALL DETAILS\n'+'*'*20+'\n')
        pf.write('{}Firewall Status :{} {} | Default status : {}\n'.format(COLORS['BLUE'], \
COLORS['END'], firewall, 'active and enabled'))
        if port:
            pf.write('{}Ports opened :{} {}\n'.format(COLORS['BLUE'], COLORS['END'], port))
        if service:
            pf.write('{}Firewall Services Enabled :{} {}\n'.format(COLORS['BLUE'],\
 COLORS['END'], service))
        if icmp:
            pf.write('{}icmp blocks Enabled :{} {}\n'.format(COLORS['BLUE'], COLORS['END'], icmp))
        if rich_rules:
            pf.write('{}Rich Rules :{} \n{}\n'.format(COLORS['BLUE'], COLORS['END'], rich_rules))
        pf.write('\n'+'*'*20+'\nSERVICE STATUS\n'+'*'*20+'\n')
        for s_name, s_status in zip(services.keys(), service_s):
            pf.write('{}{} Status :{} {} | Default status : {}\n'.format(COLORS['BLUE'], \
s_name, COLORS['END'], s_status, ', '.join(services[s_name])))
        pf.write('\n'+'*'*20+'\nENVIRONMENT VARIABLE INFO\n'+'*'*20+'\n')
        pf.write('{}TMOUT : {}{}\n'.format(COLORS['BLUE'], COLORS['END'], tmout))
        pf.write('{}XTERM Variable :{} {}\n'.format(COLORS['BLUE'], COLORS['END'], xterm_var))
        pf.write('\n'+'*'*20+'\nLV and FS Status\n'+'*'*20+'\n')
        if boot_error:
            pf.write('{}FS errors : {} \n{}\n'.format(COLORS['BLUE'], COLORS['END'], boot_error))
        pf.write('{}LV and Snapshot :{} \n{}\n'.format(COLORS['BLUE'], COLORS['END'], l_volume))
        pf.write('\n'+'*'*20+'\nMOUNT Status\n'+'*'*20+'\n')
        pf.write('{}Mount Points :{} \n{}\n'.format(COLORS['BLUE'], COLORS['END'], mnt))
    os.chmod(POST_FILE, 0o550)
