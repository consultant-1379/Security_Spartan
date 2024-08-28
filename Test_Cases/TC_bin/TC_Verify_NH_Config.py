#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2019 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : TC_Verify_NH_Config.py
# Purpose   : Test Case to verify ports and services
#
# ********************************************************************
"""

import os
import commands as c
import time
import logging

def NH_conf():
    check_mount_point = os.path.ismount("/JUMP")
    mws_insttype_path = os.path.exists("/ericsson/config/inst_type")
    eniq_insttype_path = os.path.exists("/eniq/installation/config/")

    if mws_insttype_path is True:
        mws_insttype = c.getoutput("cat /ericsson/config/inst_type")
        server_config_name = c.getoutput("cat /ericsson/config/ericsson_use_config | cut -d'=' -f 2")
        if (check_mount_point != True) or ('rhelonly' not in mws_insttype) or ('mws' not  in server_config_name):
	    print "MWS not configured"
	    logging.info("MWS not configured")
            return "FAIL"
			
    if os.path.exists("/var/tmp/TC_bin/Ports") == False:
        logging.info("/var/tmp/TC_bin/Ports not available")
	print "/var/tmp/TC_bin/Ports not available"
        return "FAIL"

	needed = open('/var/tmp/TC_bin/Ports','r').read().splitlines()[1].split()
	ports = c.getoutput("firewall-cmd --list-ports").split()
	for p in ports:
	    if p not in needed:
		print "%s not opened" % p
		logging.info("%s not opened" % p)
		return "FAIL"
	if len(needed) != len(ports):
	    logging.info("Error in opened ports")
	    print "Error in opened ports"
	    return "FAIL"

	service = c.getoutput("firewall-cmd --list-services --zone=internal").split()
	if 'mountd' not in service:
	    print "mountd service not enabled"
	    logging.info("mountd service not enabled")
	    return "FAIL"
            
	bools = ['nfs_export_all_rw']
	for b in bools:
	    check = c.getoutput("getsebool "+b+" | awk '{print $3}'")
	    if check != 'on':
		print "%s not setbool in SE" % b
		logging.info("%s not setbool in SE" % b)
		return "FAIL"

    elif eniq_insttype_path is True:
	needed = open('/var/tmp//TC_bin/Ports','r').read().splitlines()[3].split()
	ports = c.getoutput("firewall-cmd --list-ports").split()
	for p in ports:
            if p not in needed:
		print "%s not opened" % p
		logging.info("%s not opened" % p)
                return "FAIL"

        if len(needed) != len(ports):
	    print "Error in opened ports"
            logging.info("Error in opened ports")
            return "FAIL"

	need_service = ['nfs', 'mountd', 'rpc-bind']
	service = c.getoutput("firewall-cmd --list-services").split()
	for n in need_service:
	    if n not in service:
		print "%s service not open" % n
		logging.info("%s service not open" % n)
		return "FAIL"
                
	bools = ['kdumpgui_run_bootloader', 'use_nfs_home_dirs']
	for b in bools:
            check = c.getoutput("getsebool "+b+" | awk '{print $3}'")
            if check != 'on':
		print "%s not setbool in SE" % b
		logging.info("%s not setbool in SE" % b)
                return "FAIL"

    else:
	print "SERVER not configured"
	logging.info("SERVER not configured")
        return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_Verify_NH_Config.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    """
    status = os.system("/ericsson/security/bin/Verify_NH_Config.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/Verify_NH_Config.py error")
        print "FAIL"
        exit()
    """
    print NH_conf()
