#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_verify_static_ip_config.py'
# Purpose   : Test script to check dynamic IP allocation for IPv4 is disabled.
# ********************************************************************
"""
import os
import commands as c
import time
import logging

def static():

    data = c.getoutput("ls /sys/class/net/ | grep -v lo | grep -v bonding_masters").split()
    if data == []:
        print "ifcfg-eno files not found in /etc/sysconfig/network-scripts/"
        logging.info("ifcfg-eno files not found in /etc/sysconfig/network-scripts/")
        return "FAIL"
    for file in data:
        f = "/etc/sysconfig/network-scripts/ifcfg-"+file
        check = open(f, 'r').readlines()
        if "BOOTPROTO=dhcp\n" in check:
            print "dhcp enabled"
            logging.info("dhcp enabled")
            return "FAIL"
        if "BOOTPROTO=static\n" not in check and "BOOTPROTO=none\n" not in check and 'BOOTPROTO="static"\n' not in check:
            print "BOOTPROTO=static not in network scripts"
            logging.info("BOOTPROTO=static not in network scripts")
            return "FAIL"
	if os.path.exists('/ericsson/security/BACKUP_CONFIG_FILES/INTRFC_CONFIG_FILES/ifcfg-'+file) == False:
	    continue
        diff = c.getoutput('diff '+f+' /ericsson/security/BACKUP_CONFIG_FILES/INTRFC_CONFIG_FILES/ifcfg-'+file).split('\n')
	if len(diff) != 4:
	    print "Additional changes in interface files"+'\n'.join(diff)
	    logging.info("Additional changes in interface files")
	    return "FAIL"
	elif diff[1] != '< BOOTPROTO=static':
	    print "Changes in interface files are not relevant"
	    logging.info("Changes in interface files are not relavent")
	    return "FAIL"
	if os.path.exists(f+'.bak'):
	    print ".BAK file present. do essential messures"
	    logging.info(".BAK file present. do essential messures")
	    
    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_verify_static_ip_config.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/verify_static_ip_config.py > /dev/null 2>&1")
    if status != 0:
        logging.info("/ericsson/security/bin/verify_static_ip_config.py error")
        print "FAIL"
        exit()

    print static()
