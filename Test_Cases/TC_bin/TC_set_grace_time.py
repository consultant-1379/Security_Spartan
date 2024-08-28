#!/usr/bin/python

import os
import time
import logging
import commands as c

def grace():

    data = open('/etc/ssh/sshd_config','r').read().split('\n')
    if 'LoginGraceTime 1m' not in data:
	print "not set grace time"
	logging.info("not set grace time")
	return "FAIL"
        
    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_grace_time.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    if os.path.exists('/etc/ssh/sshd_config') == False:
	logging.info("/etc/ssh/sshd_config not found")
        print "FAIL"
        exit()
    check = open('/etc/ssh/sshd_config','r').read().split('\n')

    status = os.system("/ericsson/security/bin/set_grace_time.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/set_grace_time.py error")
        print "FAIL"
        exit()
    data = open('/etc/ssh/sshd_config','r').read().split('\n')

    for line in data:
        if line not in check and line != 'LoginGraceTime 1m':
	    logging.info("%s not found earlier" % line)
            print "FAIL"
            exit()

    print grace()