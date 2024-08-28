#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_mask_alt_ctrl_del.py
# Purpose   : Test script to verify Ctrl+Alt+Del key to reboot is disabled.
# ********************************************************************
"""

import os
import commands as c
import time
import logging

def masking():

    if c.getoutput("systemctl status ctrl-alt-del.target | grep Loaded: |cut -d':' -f2|cut -d' ' -f2") != "masked":
	print "not masked ctrl+alt+del"
	logging.info("not masked ctrl+alt+del")
        return "FAIL"
       
    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_mask_alt_ctrl_del.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/mask_alt_ctrl_del.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/mask_alt_ctrl_del.py error")
        print "FAIL"
        exit()

    print  masking()

