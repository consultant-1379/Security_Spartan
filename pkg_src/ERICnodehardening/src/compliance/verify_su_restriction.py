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
# Name      : verify_su_restriction.py
# Purpose   : This script is to verify the su access restriction
# Author    : Pradeep Kumar Doddagoudar
# Date      : 05-07-2021
# Revision  : A
# Reason    : EQEV-88538
# ********************************************************************
# History
"""

import subprocess
import commands
import logging
import sys
sys.path.insert(0, '/ericsson/security/bin')
from su_restriction import server_type
def check_restriction():
    """This function verifies whether su restriction is enforced or not"""
    try:
        check_present = subprocess.\
            check_output("cat /etc/group | grep -iw sugroup | cut -d':' -f 1", shell=True)
        check_present = check_present.strip()
        type_of_server = server_type()
        type_of_eniq_server = subprocess.check_output("dmidecode -t chassis | grep Type",
                                                      shell=True)
        non_comp = "NON-COMPLIANT: EXECUTE 'su_restriction.py' TO MAKE IT COMPLIANT"
        if check_present != "sugroup":
            logging.info("sugroup is not created")
            return non_comp
        check_users = subprocess.check_output("cat /etc/group | grep -iw sugroup | cut -d':' -f 4",
                                              shell=True)
        check_users = check_users.strip().split(',')
        if type_of_server == "MWS":
            if "root" not in  check_users:
                logging.info("MWS users are not added into the group")
                return non_comp
        elif type_of_server == "ENIQ-S":
            if type_of_eniq_server.strip() == ("Type: Rack Mount Chassis"):
                if "dcuser" not in check_users or "root" not in check_users:
                    logging.info("ENIQ-S users are not added into the group")
                    return non_comp
            else:
                if "storadm" not in check_users or "dcuser" not in check_users \
                        or "root" not in check_users:
                    logging.info("ENIQ-S users are not added into the group")
                    return non_comp
        with open("/etc/pam.d/su", 'r') as fin:
            data = fin.readlines()
        configured_line = "auth            required        pam_wheel.so use_uid group=sugroup\n"
        if configured_line not in data:
            logging.info(non_comp)
            return non_comp
        return"COMPLIANT"
    except(IOError, RuntimeError, AttributeError, TypeError):
        print"Could not verify su restriction"
        logging.error("Could not verify su restriction")
if __name__ == '__main__':
    check_restriction()
