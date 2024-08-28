#!/usr/bin/python
"""
# ********************************************************************
# Name      : NTC_enable_firewall.py
# Purpose   : Test script to check that recommended values are set for password aging.
#
# ********************************************************************
"""
import os
import subprocess as s
import commands as c
import time
import logging

def firewall():

    check1 = s.check_output("systemctl status firewalld | grep -i Active | cut -d':' -f 2 | cut -d ' ' -f 2", shell= True)
    check2 = s.check_output("systemctl status firewalld | grep Loaded | cut -d ';' -f 2 | cut -d ' ' -f 2", shell = True)

    if check1 != "active\n" or check2 != "enabled\n":
	print "Firewall not active"
	logging.info("Firewall not active")
	return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_enable_firewall.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/enable_firewall.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
	logging.info("/ericsson/security/bin/enable_firewall.py error")
	exit()

    print firewall()
