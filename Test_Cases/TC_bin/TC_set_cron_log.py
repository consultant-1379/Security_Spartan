#!/usr/bin/python
"""
# ********************************************************************
# Name       : TC_set_cron_log.py
# Purpose    : Test script to check configuration of logrotate for cron log.
#
# ********************************************************************
"""
import os
import subprocess as s
import commands as c
import time
import logging

def set_cron():

    if os.path.exists("/etc/logrotate.d/syslog") == False:
	print "/etc/logrotate.d/syslog not found"
	logging.info("/etc/logrotate.d/syslog not found")
        return "FAIL"
        
    if os.path.exists("/ericsson/security/bin/Cron_Log") == False:
	print "/ericsson/security/bin/Cron_Log not found"
	logging.info("/ericsson/security/bin/Cron_Log not found")
        return "FAIL"
        
    data=['/var/log/maillog', '/var/log/messages', '/var/log/secure',
          '/var/log/spooler', '{','    rotate 8', '    missingok', '    compress',
          '    notifempty','    size 1M', '    sharedscripts', '    postrotate',
          '\t/bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true',
          '    endscript', '}', '']
    
    if os.path.exists("/etc/logrotate.d/cron") == False:
	print "/etc/logrotate.d/cron not found"
	logging.info("/etc/logrotate.d/cron not found")
        return "FAIL"
        
    data1 = open('/etc/logrotate.d/syslog', 'r').read().split('\n')
    if data != data1:
	print "/etc/logrotate.d/syslog log not set"
	logging.info("/etc/logrotate.d/syslog log not set")
	return "FAIL"
        
    data = open('/ericsson/security/bin/Cron_Log','r').read().split('\n')
    data.remove('')
    data.insert(0, '/var/log/cron')
    data.insert(1,'{')
    data.insert(-1, '}')

    if s.check_output("ls -l /etc/logrotate.d/cron | cut -f1 -d' '", shell = True) != "-rw-r--r--.\n":
	logging.info("Permission not set")
	print "Permission not set"
	return "FAIL"
        
    data1 = open('/etc/logrotate.d/cron','r').read().split('\n')
    if data != data1:
	print "/etc/logrotate.d/cron log not set"
	logging.info("/etc/logrotate.d/cron log not set")
        return "FAIL"
    
    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_cron_log.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/set_cron_log.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
	logging.info("/ericsson/security/bin/set_cron_log.py error")
        exit() 

    print set_cron()
