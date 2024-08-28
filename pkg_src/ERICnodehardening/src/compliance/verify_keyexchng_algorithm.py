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
# Name      : verify_keyexchng_algorithm.py
# Purpose   : This script verifies if Key Exchange algorithms are
#             configured or not
# Reason    : EQEV-92523
# Revision  : A
#*********************************************************************
"""
import subprocess
import logging

def check_kex():
    """This script verifies if the recommended set of Key Exchange algorithms \
are added or not"""
    with open('/etc/ssh/sshd_config', 'r') as fin:
        data = fin.read()
    with open('/etc/ssh/ssh_config', 'r') as fout:
        data1 = fout.read()

    kex_algos = 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,\
diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,\
ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256\n'

    if kex_algos in data and kex_algos in data1:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT: EXECUTE 'add_keyexchng_algorithm.py' TO MAKE IT COMPLIANT"
if __name__ == '__main__':
    check_kex()
