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
# Name      : verify_path_integrity.py
# Purpose   : This script is to verify the root PATH integrity
# Author    : Pradeep Kumar Doddagoudar
# Date      : 02-07-2021
# Revision  : A
# Reason    : EQEV-90265
# ********************************************************************
# History
"""
import commands
import logging
def check_integrity():
    """This fundction verifies root PATH integrity"""
    try:
        dirs = commands.getoutput("echo $PATH")
        dirs = dirs.split(":")
        if "/root/bin" not in dirs:
            return"COMPLIANT"
        else:
            return"NON-COMPLIANT: EXECUTE 'set_path_integrity.py' TO MAKE IT COMPLIANT"
    except(IOError, RuntimeError, AttributeError, TypeError):
        print"Could not verify root PATH integrity"
        logging.error("Could not verify root PATH integrity")
if __name__ == '__main__':
    check_integrity()
