#!/usr/bin/python
"""
# ********************************************************************
# Name       : TC_restrict_at.py
# Purpose    : Test script to check whether the permission of users to configure at jobs is restricted.
#
# ********************************************************************
"""
import os
import time
import logging
import commands as c

def permit_at():

    if os.path.exists("/ericsson/security/bin/at_conf") == False:
	print "/ericsson/security/bin/at_conf not found"
	logging.info("/ericsson/security/bin/at_conf not found")
        return "FAIL"

    lines = open('/ericsson/security/bin/at_conf', 'r').read().split('\n')

    if os.path.exists("/etc/at.allow") == False:
	print "/etc/at.allow not found"
        logging.info("/etc/at.allow not found")
	return "FAIL"
      
    check1 = open('/etc/at.allow','r').read().split('\n')

    if os.path.exists("/etc/at.deny") == False:
	print "/etc/at.deny not found"
	logging.info("/etc/at.deny not found")
        return "FAIL"

    check2 = open('/etc/at.deny','r').read().split('\n')

    for line in lines:
        if 'Allow' in line:
            Allow  = line.split()[1:]
        elif 'Deny' in line:
            Deny = line.split()[1:]

    for c in check1:
        if c not in Allow and c != "":
	    logging.info("%s not in allow" % c)
	    print "%s not in allow" % c
            return "FAIL"
    for c in check2:
        if c not in Deny and c!="":
	    logging.info("%s not in deny" % c)
	    print "%s not in deny" % c
            return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_restrict_at.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/restrict_at.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/restrict_at.py error")
        print "FAIL"
        exit()


    print permit_at()
