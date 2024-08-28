#!/usr/bin/python

import time
import logging
import subprocess as s
import os
import commands as c

def TC_se():

    if s.check_output("getenforce", shell = True) != "Enforcing\n":
        logging.info("NOT Enforced")
        print "NOT Enforced"
        return "FAIL"

    config_file = open("/etc/sysconfig/selinux", "r").read()
    if "SELINUX=enforcing" not in config_file:
        return "FAIL"

    return "SUCCESS"

if __name__ == "__main__":

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_enforce_selinux.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/enforce_selinux.py > /dev/null 2>&1")

    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/enforce_selinux.py error")
        exit()

    print TC_se()
