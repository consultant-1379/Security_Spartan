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
# Name      : pre_nh_checks.py
# Purpose   : This script checks and logs the status of the server before Node hardening.
#
# ********************************************************************
"""

import os
import logging
import time
import commands

class Precheck:
    """This class is used to check the status of server before Node hardening"""
    def __init__(self, file_name):
        self.WAR = 0
        self.COLORS = {'RED':'\33[31m', 'END':'\033[0m', 'GREEN':'\33[32m',
                       'YELLOW':'\33[33m', 'BLUE':'\33[94m'}
        self.PRE_FILE = file_name
        if os.path.exists(self.PRE_FILE) and os.stat(self.PRE_FILE).st_size != 0:
            t = open(self.PRE_FILE, 'r').readlines()[0].replace('\n', '')
            n = self.PRE_FILE.replace('NH_Logs/', 'NH_Logs/'+t)
            os.system("cp {} {}".format(self.PRE_FILE, n))
            os.system("rm -rf {}".format(self.PRE_FILE))
        open(self.PRE_FILE, 'w')

    def find_deployment(self):
        """Function to find the deployment"""
        check_mount_point = os.path.ismount("/JUMP")
        mws_insttype_path = os.path.exists("/ericsson/config/inst_type")
        eniq_insttype_path = os.path.exists("/eniq/installation/config/")
        if mws_insttype_path:
            mws_insttype = commands.getoutput("cat /ericsson/config/inst_type")
            server_config_name = commands.getoutput("cat /ericsson/config/ericsson_use_config |\
 cut -d'=' -f 2").replace('\n', '')
            if check_mount_point and 'rhelonly' in mws_insttype and 'mws' in server_config_name:
                return 'MWS'
        if eniq_insttype_path:
            return 'ENIQ'
        self.WAR += 1
        logging.warning('Server not configured either as MWS nor as Eniq.')
        return self.COLORS['YELLOW']+'Not configured either as MWS nor as Eniq'+self.COLORS['END']

    def find_type(self):
        """Function to find the server type"""
        name = commands.getoutput("dmidecode -t system| grep -i 'Product Name'").split(': ')[1]
        chassis = commands.getoutput("dmidecode -t chassis| grep Type").split(': ')[1]
        return ', '.join([name, chassis])

    def find_lvs(self):
        """Function to find lvs"""
        lvs = commands.getoutput("lvs")
        fmt = commands.getoutput("findmnt -l")
        output = (lvs, fmt)
        return output

    def firewall_details(self, firewall_s):
        """Function to check firewall details"""
        active_status = commands.getoutput("systemctl status firewalld | grep -i Active | \
cut -d':' -f 2 | cut -d ' ' -f 2").replace('\n', '')
        enabled_status = commands.getoutput("systemctl status firewalld | sed -n '/Loaded:/p' \
| cut -d ';' -f 2 | cut -d ' ' -f 2").replace('\n', '')
        ports, service, icmp, rules = '', '', '', ''
        if active_status == 'active':
            ports = commands.getoutput("firewall-cmd --list-ports")
            service = commands.getoutput("firewall-cmd --list-services")
            rules = commands.getoutput("firewall-cmd --list-rich")
            icmp = commands.getoutput("firewall-cmd --list-icmp")
        if active_status == firewall_s[0] and enabled_status == firewall_s[1]:
            output = (active_status+' '+enabled_status, ports, service, icmp, rules)
            return output
        self.WAR += 1
        logging.warning('Firewall is not inactive and disabled.')
        if active_status != firewall_s[0]:
            active_status = self.COLORS['YELLOW']+active_status+self.COLORS['END']
        if enabled_status != firewall_s[1]:
            enabled_status = self.COLORS['YELLOW']+enabled_status+self.COLORS['END']
        output = (active_status+', '+enabled_status, ports, service, icmp, rules)
        return output

    def find_var(self, exp):
        """Function to find variable"""
        tvar = commands.getoutput("echo $TERM").replace('\n', '')
        tmout = commands.getoutput("echo $TMOUT")
        if tvar and tmout == exp:
            if not tmout:
                tmout = 'Not Enforced'
            output = (tmout, tvar)
            return output
        self.WAR += 1
        if not tvar:
            tvar = self.COLORS['YELLOW']+'Not Found'+self.COLORS['END']
        if tmout:
            tmout = self.COLORS['YELLOW']+tmout+self.COLORS['END']
        else:
            tmout = self.COLORS['YELLOW']+'Not Enforced'+self.COLORS['END']
        logging.warning('TERM variable not found.')
        output = (tmout, tvar)
        return output

    def find_service_status(self, serv):
        """Function to find the service status"""
        status = []
        for service in serv.keys():
            a_status = commands.getoutput("systemctl status {} |grep -i Active |cut -d':' -f 2 |\
 cut -d ' ' -f 2".format(service)).replace('\n', '')
            b_status = commands.getoutput("systemctl status {} |sed -n '/Loaded:/p'| cut -d ';' \
-f 2 | cut -d ' ' -f 2".format(service)).replace('\n', '')
            if a_status != serv[service][0] or b_status != serv[service][1]:
                self.WAR += 1
                logging.warning('%s is %s and %s.', service, a_status, b_status)
                if b_status != serv[service][1]:
                    b_status = self.COLORS['YELLOW']+b_status+self.COLORS['END']
                if a_status != serv[service][0]:
                    a_status = self.COLORS['YELLOW']+a_status+self.COLORS['END']
            status.append(a_status + ', '+  b_status)
        return status

    def check_fs(self):
        """Function to check the files"""
        files = commands.getoutput("ls -t /var/log/ | grep boot.log | head -n2").split('\n')
        log_file = ''
        for check in files:
            if check and os.stat("/var/log/"+check).st_size != 0:
                log_file = "/var/log/"+check
                break
        if log_file:
            lfc = commands.getoutput("cat {} | grep -i 'failed for'".format(log_file))
            if lfc:
                self.WAR += 1
                lfc = self.COLORS['YELLOW']+lfc+self.COLORS['END']
            return lfc
        return ''

    def start_pre_check(self):
        """Function to verify pre check status"""
        services = {'sshd':('active', 'enabled'), 'nfs':('inactive', 'enabled'),
                    'crond':('active', 'enabled'), 'rsyslog':('active', 'enabled'),
                    'named':('active', 'enabled'), 'rpcbind':('active', 'enabled'),
                    'kdump':('active', 'enabled'), 'ntpd':('inactive', 'disabled'),
                    'auditd':('active', 'enabled')}
        server_deployment = self.find_deployment()
        logging.info('Captured Server Deployment')
        server_type = self.find_type()
        logging.info('Captured Server Hardware Type')
        l_volume, mnt = self.find_lvs()
        logging.info('Captured Server LV, VG, Mounted FS')
        boot_error = self.check_fs()
        logging.info('Captured the status of File Systems')
        firewall, port, service, icmp, rich_rules = self.firewall_details(['inactive', 'disabled'])
        logging.info('Captured Server Firewall details')
        tmout, xterm_var = self.find_var('')
        logging.info('Captured Server Time out and Term variable')
        service_s = self.find_service_status(services)
        logging.info('Captured Services status')
        timestr = time.strftime("%Y%m%d-%H%M%S")
        with open(self.PRE_FILE, 'a') as pf:
            pf.write('{}\n'.format(timestr))
            pf.write('{}Warnings Found : {}{}\n'.format(self.COLORS['YELLOW'],\
self.WAR, self.COLORS['END']))
            pf.write('\n'+'*'*20+'\nSERVER INFORMATION\n'+'*'*20+'\n')
            pf.write('{}Server Deployment :{} {}\n'.format(self.COLORS['BLUE'], \
self.COLORS['END'], server_deployment))
            pf.write('{}Server Type :{} {}\n'.format\
(self.COLORS['BLUE'], self.COLORS['END'], server_type))
            pf.write('\n'+'*'*20+'\nFIREWALL DETAILS\n'+'*'*20+'\n')
            pf.write('{}Firewall Status :{} {} | Default status : \
{}\n'.format(self.COLORS['BLUE'], \
self.COLORS['END'], firewall, 'inactive and disabled'))
            if port:
                pf.write('{}Ports opened :{} {}\n'.format\
(self.COLORS['BLUE'], self.COLORS['END'], port))
            if service:
                pf.write('{}Firewall Services Enabled :{} {}\n'.format(self.COLORS['BLUE'],\
 self.COLORS['END'], service))
            if icmp:
                pf.write('{}icmp blocks Enabled :{} {}\n'.format(self.COLORS['BLUE'],\
 self.COLORS['END'], icmp))
            if rich_rules:
                pf.write('{}Rich Rules :{} \n{}\n'.format(self.COLORS['BLUE'], \
self.COLORS['END'], rich_rules))
            pf.write('\n'+'*'*20+'\nSERVICE STATUS\n'+'*'*20+'\n')
            for s_name, s_status in zip(services.keys(), service_s):
                pf.write('{}{} Status :{} {} | Default status : {}\n'.format(self.COLORS['BLUE'], \
s_name, self.COLORS['END'], s_status, ', '.join(services[s_name])))
            pf.write('\n'+'*'*20+'\nENVIRONMENT VARIABLE INFO\n'+'*'*20+'\n')
            pf.write('{}TMOUT : {}{}\n'.format(self.COLORS['BLUE'], self.COLORS['END'], tmout))
            pf.write('{}XTERM Variable :{} {}\n'.format(self.COLORS['BLUE'], \
self.COLORS['END'], xterm_var))
            pf.write('\n'+'*'*20+'\nLV and FS Status\n'+'*'*20+'\n')
            pf.write('{}LV and Snapshot :{} \n{}\n'.format(self.COLORS['BLUE'], \
self.COLORS['END'], l_volume))
            pf.write('\n'+'*'*20+'\nMOUNT Status\n'+'*'*20+'\n')
            pf.write('{}Mount Points :{} \n{}\n'.format\
(self.COLORS['BLUE'], self.COLORS['END'], mnt))
            if boot_error:
                pf.write('{}File system errors : {} \n{}\n'.format(self.COLORS['BLUE'], \
self.COLORS['END'], boot_error))
        os.chmod(self.PRE_FILE, 0o550)
