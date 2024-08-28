#!/usr/bin/python

import time
import logging
import os
import subprocess as s
import commands as c

def icmp_configure():
    
    active_status = s.check_output("systemctl status firewalld | grep -i Active | cut -d':' -f 2 | cut -d ' ' -f 2", shell=True)
    enabled_status = s.check_output("systemctl status firewalld | sed -n '/Loaded:/p' | cut -d ';' -f 2 | cut -d ' ' -f 2", shell=True)

    if active_status == "inactive\n" or enabled_status == "disabled\n":
	logging.info("Firewall not enabled")
        print "Firewall not enabled"
        return "FAIL"

    icmp_types = ["redirect", "timestamp-reply", "router-solicitation", "router-advertisement"]
    for i in icmp_types:
        cmd = "firewall-cmd --query-icmp-block=%s" % i
#        icmp_status = s.check_output(cmd , shell = True)
        icmp_status = c.getoutput(cmd)
        if icmp_status != 'yes':
	    logging.info("ICMP not blocked")
	    print "ICMP not blocked"
            return "FAIL"

    if 'net.ipv4.icmp_echo_ignore_all = 0' not in open('/etc/sysctl.conf').read().split('\n'):
	logging.info("ICMP ECHO not ignored")
	print "ICMP ECHO not ignored"
        return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_configure_icmp.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/configure_icmp.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/configure_icmp.py error")
        print "FAIL"
        exit()

    print icmp_configure()
