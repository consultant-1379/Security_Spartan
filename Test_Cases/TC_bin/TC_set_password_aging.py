#!/usr/bin/python

import os
import commands as c
import time
import logging

def pass_age():

    users = open("/etc/passwd",'r').readlines()
    for user in users:
	data1 = user.split(':')
        if (data1[0] != "dcuser") and (data1[0] != "root") and (data1[0] != "storadm") and (int(data1[2]) > 999):
	    a = c.getoutput("chage -l "+data1[0]+" | tail -n 2 | cut -d':' -f2 | cut -d' ' -f2")
            if '60' not in a:
		print "age and warning not set to 60 and 7 %s" % data1[0]
		logging.info("age and warning not set to 60 and 7 %s" % data1[0])
                return "FAIL"
    	if data1[0] == "storadm":
	    a = c.getoutput("chage -l "+data1[0]+" | tail -n 2 | cut -d':' -f2 | cut -d' ' -f2")
            if '60' in a :
                print "age and warning set for %s" % data1[0]
                logging.info("age and warning set for %s" % data1[0])
                return "FAIL"

    return "SUCCESS"
   
if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_password_aging.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/set_password_aging.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/set_password_aging.py error")
        print  "FAIL"
        exit()


    print pass_age()
