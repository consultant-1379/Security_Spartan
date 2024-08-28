#!/usr/bin/python
"""
# ********************************************************************
# Name       : NTC_restrict_at.py
# Purpose    : Test script to check that only the allowed users can configure at jobs.
# ********************************************************************
"""
import os
import commands as c
import logging
import time
from TC_restrict_at import permit_at


def update_at():
    os.system("touch copyatallow.txt")
    os.system("cp /etc/at.allow copyatallow.txt")
    f= open('/etc/at.allow', 'a')
    f.write("test\n")
    f.close()
    output=permit_at()
    os.system("cp copyatallow.txt /etc/at.allow")
    os.system("rm -rf copyatallow.txt")
    update_deny()
    if output=="FAIL":
          return "SUCCESS"
    else:
          return "FAIL"

def update_deny():
    os.system("touch copyatdeny.txt")
    os.system("cp /etc/at.deny copyatdeny.txt")
    fi= open('/etc/at.deny', 'a')
    fi.write("test\n")
    fi.close()
    output=permit_at()
    os.system("cp copyatdeny.txt /etc/at.deny")
    os.system("rm -rf copyatdeny.txt")
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
    if os.path.exists("/etc/at.allow") == False:
        logging.info("/etc/at.allow not found")
        print "FAIL"
        exit()
    if os.path.exists("/etc/at.deny") == False:
        logging.info("/etc/at.deny not found")
        print "FAIL"
        exit()
    print update_at()
