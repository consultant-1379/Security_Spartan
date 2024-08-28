#!/usr/bin/python
"""
# ********************************************************************
# Name       : TC_restrict_cron.py
# Purpose    : Test script to check the permission of users to configure cron jobs is restricted.
# ********************************************************************
"""
import os
import time
import commands
import subprocess as s
import logging

def permit_cron():

    if os.path.exists("/ericsson/security/bin/cron_conf") == False:
        print "/ericsson/security/bin/cron_conf not found"
        logging.info("/ericsson/security/bin/cron_conf not found")
        return "FAIL"

    lines = open('/ericsson/security/bin/cron_conf', 'r').read().split('\n')

    if os.path.exists("/etc/cron.allow") == False:
        print "/etc/cron.allow not found"
        logging.info("/etc/cron.allow not found")
        return "FAIL"

    check1 = open('/etc/cron.allow','r').read().split('\n')

#    if os.path.exists("/etc/cron.deny") == False:
#        print "/etc/cron.deny not found"
#        logging.info("/etc/cron.deny not found")
#        return "FAIL"

    for u in check1:
        if u == '':
            continue
        output = commands.getoutput("su -c 'crontab -l' -l "+u)
        if "not allowed to use" in output:
            print "%s is not allowed" % u
            logging.info("%s is not allowed" % u)
            return "FAIL"

#    check2 = open('/etc/cron.deny','r').read().split('\n')

#    for u in check2:
#        if u == '':
#            continue
#        output = commands.getoutput("su -c 'crontab -l' -l "+u)
#        if "not allowed to use" not in output:
#            print "%s is allowed" % u
#            logging.info("%s is allowed" % u)
#            return "FAIL"

    for line in lines:
        if 'Allow' in line:
            Allow  = line.split()[1:]
        elif 'Deny' in line:
            Deny = line.split()[1:]

    for c in check1:
        if c not in Allow and c != "":
            logging.info("%s is not allowed" % c)
            print "%s is not allowed" % c
            return "FAIL"

#    for c in check2:
#        if c not in Deny and c!="":
#            logging.info("%s is not denied" % c)
#            print "%s is not denied" % c
#            return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_restrict_cron.log'
    pwd = commands.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/restrict_cron.py > /dev/null 2>&1")
    if status != 0:
        logging.info("/ericsson/security/bin/restrict_cron.py error")
        print "FAIL"
        exit()

    print permit_cron()
