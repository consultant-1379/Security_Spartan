#!/usr/bin/python

import os
import time
import logging
import commands as c
import pxssh
import subprocess
import re
#from import IP

from TC_set_password_policy import create_pass

def SSH():

    if os.path.exists("/ericsson/security/bin/username") == False:
        logging.info("/ericsson/security/bin/username not found")
        return "FAIL"

    usernames = open("/ericsson/security/bin/username","r").readlines()

    users = []

    local_host = subprocess.check_output("ip route get 1 | awk '{print $NF; exit}'", shell=True)
    ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', local_host)
    for index, value in enumerate(usernames):
        if value == "storadm\n":
            usernames[index] = value.replace('\n', '')+"@"+ ip[0]+"\n"

    users = ' '.join(usernames)
    users = users.replace('\n', '')
    users = "AllowUsers"+" "+ users
    users = users.strip()
    cmd_allowuser = "cat /etc/ssh/sshd_config | grep AllowUsers"
    process_allowuser = subprocess.Popen(cmd_allowuser, shell=True, stdout=subprocess.PIPE)
    output_allowuser = process_allowuser.stdout.read().strip()
    if users != output_allowuser:
        print "%s user not Allowed" % users
        logging.info("%s user not Allowed" % users)
        return "FAIL"
    f = pxssh.pxssh()
    try:
        password = create_pass(1,2,3,4).replace('"',"?")
        os.system('useradd testssh; echo "+pasword+" | passwd "testssh"  --stdin >/dev/null 2>&1')
        f.login ('10.45.192.138', 'testssh', password)
        f.logout()
        os.system('deluser -r testssh >/dev/null 2>&1')
        print "test user is Allowed"
        logging.info("test user is Allowed")
        return "FAIL"
    except pxssh.ExceptionPxssh:
        pass
    os.system('userdel -r testssh >/dev/null 2>&1')

    return "SUCCESS"


if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_enable_ssh_login.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    if os.path.exists("/etc/ssh/ssh_config") == False:
        logging.info("/etc/ssh/ssh_config not found")
        print "FAIL"
        exit(1)
    check = open("/etc/ssh/sshd_config","r").read().split('\n')

    status = os.system("/ericsson/security/bin/enable_ssh_login.py > /dev/null 2>&1")
    if status != 0:
        logging.info("/ericsson/security/bin/enable_ssh_login.py error")
        print "FAIL"
        exit(2)

    data = open("/etc/ssh/sshd_config","r").read().split('\n')
    for line in check:
        if line not in data and "AllowUsers " not in line:
            print "FAIL"
            logging.info("%s not present after NH" % line)
            exit(3)

    print SSH()
