#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2021 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : verify-sshd-banner.py
# Purpose   : This script verifies if sshd banner has been set with the
#             banner message or not.
# ********************************************************************
"""
import subprocess
import filecmp
def check_banner():
    """This function verifies if sshd banner has been set with the banner message or not"""
    string = ""
    file_size = subprocess.check_output("ls -lrt /etc/issue.net | cut -d' ' -f 5", shell=True).strip()
    if '#Banner none' in open('/etc/ssh/sshd_config').read().split('\n'):
        string = "NON-COMPLIANT:  EXECUTE 'set_ssh_banner.py' TO MAKE IT COMPLIANT"
    elif 'Banner /etc/issue.net' in open('/etc/ssh/sshd_config').read().split('\n'):
        if file_size == '22':
            file_name = subprocess.check_output("cat /etc/issue.net", \
shell=True, stderr=subprocess.PIPE)
            parameters = ['\S',R'Kernel \r on an \m']
            if all(word in file_name for word in parameters):
                string = "NON-COMPLIANT:  EXECUTE 'set_ssh_banner.py' TO MAKE IT COMPLIANT"
        elif file_size == '0':
            string = "NON-COMPLIANT:  EXECUTE 'set_ssh_banner.py' TO MAKE IT COMPLIANT"
        else:
            string = "COMPLIANT"
    else:
        string = "COMPLIANT"
    return string
if __name__ == '__main__':
    check_banner()