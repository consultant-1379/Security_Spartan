#!/usr/bin/python

import os
import commands as c
import time
import logging
import random
import string
import pexpect

def create_pass(symbol_count, digit_count, lowercase_count, uppercase_count):
    pwd = ""
    for i in range(0, symbol_count):
        pwd += random.choice(string.punctuation)
    for i in range(0, digit_count):
        pwd += random.choice(string.digits)
    for i in range(0, lowercase_count):
        pwd += random.choice(string.ascii_lowercase)
    for i in range(0, uppercase_count):
        pwd += random.choice(string.ascii_uppercase)
    return pwd

def check_history():
    def test():
        pas = pexpect.spawn('passwd test')
        try:
            pas.expect('New password:')
            pas.sendline(password)
            pas.expect('Retype new password:')
            pas.sendline(password)
            j =  pas.expect('New password:', timeout = 5)
            if i ==2 and j == 0:
                pas.close()
	  	os.system("userdel -r test")
                return "SUCCESS"
        except pexpect.TIMEOUT:
            pas.close()
	    os.system("userdel -r test")
            return "FAIL"
        except pexpect.EOF:
            if i != 1:
                pas.close()
		os.system("userdel -r test")
                return "FAIL"
    i = 1
    password = create_pass(4,3,2,1)
    os.system("useradd test")
    test()
    i = 2
    return test()

def password():

    weak = [create_pass(4,3,2,0), create_pass(4,3,0,2), create_pass(4,0,3,2), create_pass(0,4,3,2), create_pass(1,1,1,1)]
    logging.info("weak password tested"+', '.join(weak))
    for p in weak:
        p = p.replace("'","/")
        p = p.replace('"','?')
        cmd = "useradd testpass; echo '"+p+"' | passwd testpass  --stdin"
        check = c.getoutput(cmd)
        if 'all authentication tokens updated successfully.' in check:
            os.system("userdel -r  testpass > /dev/null 2>&1")
            print "Weak password accepted"
            logging.info("Weak password accepted")
            return "FAIL"
        os.system("userdel -r  testpass > /dev/null 2>&1")

    strong = [create_pass(4,3,2,1), create_pass(3,4,2,2), create_pass(3,2,2,2), create_pass(1,2,3,4)]
    logging.info("strong password tested"+', '.join(strong))
    for p in strong:
        p = p.replace("'","/")
        p = p.replace('"','?')
        cmd = "useradd testpass; echo '"+p+"' | passwd testpass  --stdin"
        check = c.getoutput(cmd)
        if 'all authentication tokens updated successfully.' not in check:
            os.system("userdel -r  testpass > /dev/null 2>&1")
            print "Strong password ["+p+"] not accepted"
            logging.error("Strong password "+p+" not accepted")
            return "FAIL"
        os.system("userdel -r  testpass > /dev/null 2>&1")

    if check_history() == "FAIL":
	return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + 'set_password_policy.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    status = os.system("/ericsson/security/bin/set_password_policy.py > /dev/null 2>&1")
    if status != 0:
        logging.info("/ericsson/security/bin/set_password_policy.py error")
        print "FAIL"
        exit()
    print password()
