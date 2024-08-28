#!/usr/bin/python
"""
# ********************************************************************
# Name       : NTC_restrict_cron.py
# Purpose    : Test script to check that only the allowed users can configure cron jobs.
# ********************************************************************
"""
import os
import commands as c
import logging
import time
from TC_restrict_cron import permit_cron


def update_cron():
    os.system("touch copycronallow.txt")
    os.system("cp /etc/cron.allow copycronallow.txt")
    f= open('/etc/cron.allow', 'a')
    f.write("test\n")
    f.close()
    r=permit_cron()
    os.system("cp copycronallow.txt /etc/cron.allow")
    os.system("rm -rf copycronallow.txt")
    update_deny()
    if r=="FAIL":
          return "SUCCESS"
    else:
          return "FAIL"

def update_deny():
    os.system("touch copycrondeny.txt")
    os.system("cp /etc/cron.deny copycrondeny.txt")
    fi= open('/etc/cron.deny', 'a')
    fi.write("test\n")
    fi.close()
    r=permit_cron()
    os.system("cp copycrondeny.txt /etc/cron.deny")
    os.system("rm -rf copycrondeny.txt")
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
    if os.path.exists("/etc/cron.allow") == False:
        logging.info("/etc/cron.allow not found")
        print "FAIL"
        exit()
    if os.path.exists("/etc/cron.deny") == False:
        logging.info("/etc/cron.deny not found")
        print "FAIL"
        exit()
    print update_cron()
