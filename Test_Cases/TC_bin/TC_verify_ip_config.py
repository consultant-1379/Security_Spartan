#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_verify_ip_config.py
# Purpose   : Test script to check list of ip which are not configured to any nic by verify_ip_config.py.
#
# ********************************************************************
"""
import os
import commands as c
import time
import subprocess
import logging

def ip_conf():

    subprocess.call("ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/' > some", shell=True)
    with open("./some", 'r') as fin:
        data1 = fin.read()
    if data1:
        if(data1[0].isalpha()== False | data1[0].isdigit()== False):
            print "IP not configured"
            logging.info("IP not configured")
            os.system("rm -rf some")
        else:
	    os.system("rm -rf some")
            return "SUCCESS"
    else:
        os.system("rm -rf some")
        return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_verify_ip_config.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/verify_ip_config.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/verify_ip_config.py error")
        print "FAIL"
        exit()

    print ip_conf()

