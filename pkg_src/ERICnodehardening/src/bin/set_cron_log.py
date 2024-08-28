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
# Name       : set_cron_log.py
# Purpose    : This script configures logrotate for cron log
# Config File: Cron_Log
#
# ********************************************************************
"""

import subprocess
import os
import time
import logging

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification
file_name = "/etc/logrotate.d/syslog"

def cron_log():
    """This function is to configure the log rotate for cron log"""
    backup_files(file_name, [])

    with open(file_name, 'r') as fin:
        data = fin.read()

    data = data.split('\n')
    if '/var/log/cron' in data:
        a = data.index('/var/log/cron')
        data[a] = '#/var/log/cron'
    del data[:]
    data = ['/var/log/maillog', '/var/log/messages', '/var/log/secure',
            '/var/log/spooler', '/var/log/sudo.log', '{', '    rotate 8', \
'    missingok', '    compress',
            '    notifempty', '    size 1M', '    sharedscripts', '    postrotate',
            '\t/bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true',
            '    endscript', '}', '']
    with open(file_name, 'w') as fout:
        data = fout.writelines('\n'.join(data))

    cmd1 = "[ -f /etc/logrotate.d/cron ] && echo 'File exist' || echo 'File does not exist' "
    result = subprocess.check_output(cmd1, shell=True)

    if result == 'File exist\n':
        backup_files('/etc/logrotate.d/cron', [])
   #     with open('/etc/logrotate.d/cron', 'r') as fin:
    #        data = fin.readlines()
    else:
        subprocess.call('touch /etc/logrotate.d/cron', shell=True)
        subprocess.call('chmod  644 /etc/logrotate.d/cron', shell=True)

    with open("/ericsson/security/bin/Cron_Log", 'r') as fin:
        con = fin.read()
    con = con.split('\n')
    con.remove('')
    con.insert(0, '/var/log/cron\n{')
    con.insert(-1, '}')

    with open("/etc/logrotate.d/cron", 'w') as fout:
        fout.writelines('\n'.join(con))
    print "\n*********Logrotate for cron has been successfully configured*********\n"
    logging.info('Logrotate for cron has been successfully configured')
    subprocess.call("systemctl reload crond", shell=True)

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_cron_log.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)

    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()

    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        cron_log()
    else:
        print "Failed to verify the security settings. Execute \
/ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
