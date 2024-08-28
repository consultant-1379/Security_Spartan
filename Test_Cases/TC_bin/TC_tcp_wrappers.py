#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_tcp_wrappers.py
# Purpose   : Test script to check sftp is enabled.
#
# ********************************************************************
"""
import os
import commands as c
import time
import logging

def FTP():

    if os.path.exists("/etc/hosts.allow") == False:
	print "/etc/hosts.allow not found"
	logging.info("/etc/hosts.allow not found")
        return "FAIL"

    if os.path.exists("/etc/hosts.deny") == False:
	print "/etc/hosts.deny not found"
	logging.info("/etc/hosts.deny not found")
        return "FAIL"

    data = open('/etc/hosts.deny','r').read().split('\n')
    if 'vsftpd: ALL' not in data:
	print "vsftpd: ALL not set"
	logging.info("vsftpd: ALL not set")
        return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_tcp_wrappers.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/tcp_wrappers.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/tcp_wrappers.py error")
        print "FAIL"
        exit()

    print FTP()

