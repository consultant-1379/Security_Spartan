#!/usr/bin/python
import os
import time
import logging
import commands as c
def cipher():
    if os.path.exists("/etc/ssh/sshd_config") == False:
        logging.info("/etc/ssh/sshd_config not available")
        print "/etc/ssh/sshd_config not available"
        return "FAIL"
    if os.path.exists("/etc/ssh/ssh_config") == False:
        logging.info("/etc/ssh/ssh_config not available")
        print "/etc/ssh/ssh_config not available"
        return "FAIL"
    check1 = open("/etc/ssh/sshd_config","r").read().splitlines()
    cipher, mac = False, False
    for line in check1:
        if line[:7] == 'Ciphers' and cipher == False:
            if "Ciphers aes256-ctr,aes192-ctr,aes128-ctr,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" in line:
                cipher = True
            else:
                logging.info("Ciphers aes256-ctr,aes192-ctr,aes128-ctr,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com not present")
                print "Ciphers aes256-ctr,aes192-ctr,aes128-ctr,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com not present"
                return 'FAIL'
        if line[:4] == 'MACs' and mac == False:
            if "MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" in line:
                mac = True
            else:
                logging.info("MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com")
                print "MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
                return 'FAIL'
    if cipher != True or mac != True:
        return "FAIL"
    check2 = open("/etc/ssh/ssh_config", 'r').read().split('\n')
    cipher, mac = False, False
    for line in check2:
        if line[:7] == 'Ciphers' and cipher == False:
            if "Ciphers aes256-ctr,aes192-ctr,aes128-ctr,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" not in line:
                logging.info("Ciphers aes256-ctr,aes192-ctr,aes128-ctr,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com not available")
                print "Ciphers aes256-ctr,aes192-ctr,aes128-ctr,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com not available"
                return "FAIL"
            else:
                cipher = True
        if line[:4] == 'MACs' and mac == False:
            if "MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" not in line:
                logging.info("MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com")
                print "MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
                return "FAIL"
            else:
                mac = True
    if cipher != True or mac != True:
        return "FAIL"
    return "SUCCESS"
if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_add_cipher.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    if os.path.exists("/etc/ssh/sshd_config") == False:
        print "FAIL"
        logging.info("/etc/ssh/sshd_config not available")
        exit(1)
    check = open("/etc/ssh/sshd_config","r").read().split('\n')
    if os.path.exists("/etc/ssh/ssh_config") == False:
        print "FAIL"
        logging.info("/etc/ssh/ssh_config not available")
        exit(2)
    check0 = open("/etc/ssh/ssh_config", 'r').read().split('\n')
    status = os.system("/ericsson/security/bin/add_cipher.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/add_cipher.py Error")
        exit(3)
    check1 = open("/etc/ssh/sshd_config","r").read().split('\n')
    check2 = open("/etc/ssh/ssh_config", 'r').read().split('\n')
    for line in check:
        if line not in check1:
            logging.info("%s not in /etc/sshd/sshd_config earlier" % line)
            print "FAIL"
            exit(4)
    for line in check0:
        if line not in check2:
            logging.info("%s not in /etc/ssh/sshd_config earlier" % line)
            print "FAIL"
            exit(5)
    print cipher()