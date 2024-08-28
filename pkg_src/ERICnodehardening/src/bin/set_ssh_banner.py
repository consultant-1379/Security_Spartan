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
# Name      : set_ssh_banner.py
# Purpose   : This script sets the ssh banner that gets popped
#               during very terminal login.
#Config File: banner_ssh
#
# ********************************************************************
"""
import time
import os
import logging
import subprocess
import filecmp

from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification

def ssh_ban():
    """This function sets an ssh login banner"""

    backup_files(0, ["/etc/issue.net", "/etc/ssh/sshd_config", "/etc/issue"])

    with open('/ericsson/security/bin/banner_ssh', 'r') as fin:
        data = fin.read()
    logging.info('\n'+data)
    fin.close()

    with open('/etc/ssh/sshd_config', 'r') as fin1:
        data1 = fin1.read()
    data1 = data1.split('\n')
    file_size = subprocess.check_output("ls -lrth /etc/issue.net | cut -d' ' -f 5", shell=True)

    banner = 'Banner /etc/issue.net'
    issue = '/etc/issue.net'

    if '#Banner none' not in data1 and banner not in data1:
        logging.info('Customized banner message path is found in config file!\n')

    file_size1 = subprocess.check_output("ls -lrth /etc/issue | cut -d' ' -f 5", shell=True)
    comp1 = filecmp.cmp("/ericsson/security/bin/banner_ssh", "/etc/issue")
    if file_size1 == '23\n':
        os.system("cp /ericsson/security/bin/banner_ssh /etc/issue")
        logging.info('SSH LOGIN BANNER is successfully configured in /etc/issue!\n')
    elif comp1:
        logging.info('SSH LOGIN BANNER is already configured in /etc/issue!')
    else:
        logging.info('Customized banner message found in /etc/issue!\n')

    for i in data1:
        if '#Banner none' in i:
            a = data1.index(i)
            with open(issue, 'w') as fin:
                fin.write(data)
            data1[a] = banner
            with open('/etc/ssh/sshd_config', 'w') as fout:
                fout.writelines('\n'.join(data1))
            subprocess.call(" systemctl restart sshd ", shell=True)
            print "\n*********SSH LOGIN BANNER is successfully configured on the server*********\n"
            logging.info('SSH LOGIN BANNER is successfully configured on the server')
        elif banner in i:
            comp = filecmp.cmp("/ericsson/security/bin/banner_ssh", "/etc/issue.net")
            if comp:
                print "\n**********SSH LOGIN BANNER is already configured with \
issue.net!*********\n"
                logging.info('SSH LOGIN BANNER is already configured with issue.net!')
            elif not comp and file_size == '1017\n' or file_size == '22\n':
                with open(issue, 'w') as fin:
                    fin.write(data)
                subprocess.call("systemctl restart sshd ", shell=True)
                print "\n**********SSH LOGIN BANNER is successfully updated with \
issue.net!*********\n"
                logging.info('SSH LOGIN BANNER is successfully updated with issue.net!')
            else:
                logging.info('Customized banner message found!\n')
                with open(issue, 'r') as fin:
                    data = fin.read()
                logging.info('\n'+data)
                fin.close()

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_ssh_banner.log'
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
        ssh_ban()
    else:
        print "Failed to verify the security settings. Execute \
/ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    print "Script logs are saved at : \
\033[93m/ericsson/security/log/Apply_NH_Logs/Manual_Exec/\033[00m directory!"
