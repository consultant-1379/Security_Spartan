#!/usr/bin/python

import os
import time
import logging
import commands as c

def Banner():

    if os.path.exists("/ericsson/security/bin/banner_ssh") == False:
	print "Banner file doesn't exists"
	logging.info("Banner file doesn't exists")
        return "FAIL"      
    check = open('/ericsson/security/bin/banner_ssh', 'r').read()

    data2 = open('/etc/ssh/sshd_config', 'r').read().split('\n')

    if os.path.exists("/etc/issue.net") == False:
	logging.info("banner file not exixts")
	print "banner file not exixts"
        return "FAIL"
   
    data = open('/etc/issue.net', 'r').read()

    if data != check:
	print "Banner not set"
	logging.info("Banner not set")
        return "FAIL"
 
    if 'Banner /etc/issue.net' not in data2:
	logging.info("Banner /etc/issue.net not present in sshd")
	print "Banner /etc/issue.net not present in sshd"
	return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_ssh_banner.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    if os.path.exists("/etc/ssh/sshd_config") == False:
        print "FAIL"
	logging.info("/etc/ssh/sshd_config not found")
	exit()

    data1 = open('/etc/ssh/sshd_config', 'r').read().split('\n')

    status = os.system("/ericsson/security/bin/set_ssh_banner.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/set_ssh_banner.py error")
        print "FAIL"
        exit()
    data2 = open('/etc/ssh/sshd_config', 'r').read().split('\n')

    for line in data1:
        if line not in data2 and line != '#Banner':
            print "FAIL"
	    logging("Extra line")
	    exit()

    print Banner()
