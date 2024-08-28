#!/usr/bin/python

import os
import time
import logging
import commands as c

def afterlogin():

    if os.path.exists('/ericsson/security/bin/banner_motd') == False:
	print "/ericsson/security/bin/banner_motd not found"
	logging.info("/ericsson/security/bin/banner_motd not found")
        return "FAIL"
    data = open('/ericsson/security/bin/banner_motd','r').read()

    if os.path.exists('/etc/motd') == False:
	logging.info("/etc/motd not found")
	print "/etc/motd not found"
        return "FAIL"
    data1 = open('/etc/motd','r').read()    

    if data != data1:
	print "Motd not set correctly"
	logging.info("Motd not set correctly")
        return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_motd_banner.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/set_motd_banner.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/set_motd_banner.py error")
        print "FAIL"
        exit()

    print afterlogin()
