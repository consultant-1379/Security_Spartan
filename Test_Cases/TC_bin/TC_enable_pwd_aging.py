#!/usr/bin/python

import os
import commands as c
import time
import logging

def password_age():

    check_mount_point = os.path.ismount("/JUMP")
    mws_insttype_path = os.path.exists("/ericsson/config/inst_type")
    eniq_insttype_path = os.path.exists("/eniq/installation/config/")
    
    if mws_insttype_path is True:
	mws_insttype = c.getoutput("cat /ericsson/config/inst_type")
	server_config_name = c.getoutput("cat /ericsson/config/ericsson_use_config | cut -d'=' -f 2")
	if (check_mount_point != True) or ('rhelonly' not in mws_insttype) or ('mws' not  in server_config_name):
	    logging.info("MSW not properly configured")
	    return "FAIL"

	age = ['30', '60', '90', '99999']
	war = ['7','15']
	a, w = c.getoutput("chage -l root | tail -n 2 | cut -d':' -f2 | cut -d' ' -f2").split()
	if a not in age or w not in war:
	    logging.info("AGE or WARNING NOT SET for MWS")
	    return "FAIL"

    elif eniq_insttype_path is True:
	users = ['root', 'dcuser']
	age = ['30', '60', '90', '99999']
        war = ['7','15']
	for user in users:
	    a, w = c.getoutput("chage -l "+user+" | tail -n 2 | cut -d':' -f2 | cut -d' ' -f2").split()
	    if a not in age or w not in war:
		logging.info("AGE or WARNING NOT SET for ENIQ")
                return "FAIL"

    else:
	logging.info("server not properly configured")
	return "FAIL"
       
    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_enable_pwd_aging.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    print password_age()
