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
# Name      : TC_set_umask.py
# Purpose   : Test Case to check the umask
#
# ********************************************************************
"""

import os
import time
import logging
import commands as c

def mask():

    if os.path.exists("/etc/profile") == False:
	print "/etc/profile not found"
	logging.info("/etc/profile not found")
        return "FAIL"  
    
    id = c.getoutput("cat /etc/passwd | cut -d':' -f1,3").split('\n')
    user_id = dict()
    for u in id:
	u = u.split(':')
	user_id[u[0]] = user_id.get(u[0], int(u[1]))
    #create 5 id for test users
    ids = [0, 200, 200, 1000, 1000]
    for i in range(len(ids)):
	while(ids[i] in user_id.values()):
	    ids[i] += 1
	t = 'test'+str(i+1)
	user_id[t] = user_id.get(t,ids[i])
    os.system('useradd -u '+str(ids[0])+' test1')
    os.system('useradd -u '+str(ids[1])+' test2')
    os.system('useradd -u '+str(ids[2])+' -g 99 test3')
    os.system('useradd -u '+str(ids[3])+' test4')
    os.system('useradd -u '+str(ids[4])+' -g 99 test5')
    check_umask = []
    for i in range(len(ids)):
	check_umask.append(c.getoutput("su -c 'umask' -l test"+str(i+1)))
    #delete created users
    for i in range(len(ids)):
	os.system('userdel -r test'+str(i+1)+' >/dev/null 2>&1')
    if check_umask[0] != '0022':
   	print "umask not configured for UID 0 to 199"
        logging.info("umask not configured for UID 0 to 199")
        return "FAIL"
    if check_umask[1] != '0002':
        print "umask not configured for UID 200 to 999 0002"
        logging.info("umask not configured for UID 200 to 999 0002")
        return "FAIL"
    if check_umask[2] != '0022':
        print "umask not configured for UID 200 to 999 0022"
        logging.info("umask not configured for UID 200 to 999 0022")
        return "FAIL"
    if check_umask[3] != '0022':
        print "umask not configured for UID 1000 to 60000 0022"
        logging.info("umask not configured for UID 1000 to 60000 0022")
        return "FAIL"
    if check_umask[4] != '0027':
        print "umask not configured for UID 1000 to 60000 0027"
        logging.info("umask not configured for UID 1000 to 60000 0027")
        return  "FAIL"
  
    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_umask.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    status = os.system("/ericsson/security/bin/set_umask.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/set_umask.py error")
        print "FAIL"
        exit()
    print mask()
