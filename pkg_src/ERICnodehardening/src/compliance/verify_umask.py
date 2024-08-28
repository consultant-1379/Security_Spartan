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
# Name      : verify_umask.py
# Purpose   : This script verifies the umask value is enforced on the
#             system
# ********************************************************************
"""
import logging

def check_umask():
    try:
        """This function is to check the umask value"""
        if '''if [ $UID -gt 199 ] && [ "`/usr/bin/id -gn`" = "`/usr/bin/id -un`" ]; then\n    \
umask 027\nelse\n    umask 022\nfi\n''' in open('/etc/profile').read():
            return "COMPLIANT"
        else:
            return "NON-COMPLIANT:  EXECUTE 'set_umask.py' TO MAKE IT COMPLIANT"
    except(IOError, RuntimeError, AttributeError, TypeError):
        logging.error("Could not verify umask value")

if __name__ == '__main__':
    check_umask()
