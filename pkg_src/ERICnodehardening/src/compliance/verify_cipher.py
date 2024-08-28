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
# Name      : verify_cipher.py
# Purpose   : This script verifies if the recommended set of ciphers
#             and MACs are added or not
# Reason    : EQEV-90266
# Revision  : B
#*********************************************************************
"""

def check_cipher():
    """This script verifies if the recommended set of ciphers and MACs are added or not"""
    with open('/etc/ssh/sshd_config', 'r') as fin:
        data = fin.read()
    with open('/etc/ssh/ssh_config', 'r') as fout:
        data1 = fout.read()

    cipher = 'Ciphers aes256-ctr,aes192-ctr,aes128-ctr,chacha20-poly1305@openssh.com,' \
             'aes256-gcm@openssh.com,aes128-gcm@openssh.com'
    mac = 'MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,' \
          'hmac-sha2-256-etm@openssh.com'
    if cipher and mac in data:
        return "COMPLIANT"
    elif cipher and mac in data1:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT: EXECUTE 'add_cipher.py' TO MAKE IT COMPLIANT"
if __name__ == '__main__':
    check_cipher()
