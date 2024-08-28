#!/usr/bin/python
"""
# ******************************************************************************
# Test Case ForGranular Node Hardening                             SCRIPT
# ******************************************************************************
#
# ******************************************************************************
# Name      : GranularNH_Test.py
# Purpose   : This script is to verify Granular Node Hardening.
#             
# ******************************************************************************
"""

import time
import os
import logging
import commands as c

def Granular_NH():
    if os.path.exists('/ericsson/security/Test_Cases/granular.txt') == True:
        os.system("rm -rf /ericsson/security/Test_Cases/granular.txt > /dev/null 2>&1")
    status = "**********Successfully disabled X11Forwarding for SSH communication on the server**********\n"
    print"Executing disable_X11Forwarding.py"
    os.system("/ericsson/security/bin/disable_X11Forwarding.py > /ericsson/security/Test_Cases/granular.txt") 
    with open('/ericsson/security/Test_Cases/granular.txt', 'r') as file1:    
        if status in file1:
            print"SUCCESS"
            logging.info("Successfully executed disable_X11Forwarding.py")
        else:
            print"FAIL"
            logging.info("Failed to exceute disable_X11Forwarding.py")
    status = "********** AllowTcpForwarding for SSH communication on the server is already disabled *********\n"
    print"Executing disable_AllowTcpForwarding.py"
    os.system("/ericsson/security/bin/disable_AllowTcpForwarding.py > /ericsson/security/Test_Cases/granular.txt")
    with open('/ericsson/security/Test_Cases/granular.txt', 'r') as file1:
        if status in file1:
            print"SUCCESS"
            logging.info("Successfully executed disable_AllowTcpForwarding.py")
        else:
            print"FAIL"
            logging.info("Failed to exceute disable_AllowTcpForwarding.py")
    status = "**********Gateway ports are already disabled*********\n"
    print"Executing disable_GatewayPorts.py"
    os.system("/ericsson/security/bin/disable_GatewayPorts.py > /ericsson/security/Test_Cases/granular.txt")
    with open('/ericsson/security/Test_Cases/granular.txt', 'r') as file1:
        if status in file1:
            print"SUCCESS"
            logging.info("Successfully executed disable_GatewayPorts.py")
        else:
            print"FAIL"
            logging.info("Failed to exceute disable_GatewayPorts.py")
    status = "**********Successfully disabled broadcast ICMP packages**********\n" 
    print"Executing disable_icmp_broadcast.py"
    os.system("/ericsson/security/bin/disable_icmp_broadcast.py > /ericsson/security/Test_Cases/granular.txt")
    with open('/ericsson/security/Test_Cases/granular.txt', 'r') as file1:
        if status in file1:
            print"SUCCESS"
            logging.info("Successfully executed disable_icmp_broadcast.py")
        else:
            print"FAIL"
            logging.info("Failed to exceute disable_icmp_broadcast.py")
    status = "**********Password aging has been set to 60 days for all users, except root,dcuser,storadm and storobs!**********\n"
    print"Executing set_password_aging.py"
    os.system("/ericsson/security/bin/set_password_aging.py > /ericsson/security/Test_Cases/granular.txt")
    with open('/ericsson/security/Test_Cases/granular.txt', 'r') as file1:
        if status in file1:
            print"SUCCESS"
            logging.info("Successfully executed set_password_aging.py")
        else:
            print"FAIL"
            logging.info("Failed to exceute set_password_aging.py")
    status = "***************Successfully set the file permissions***************\n"
    print"Executing set_file_permissions.py"
    os.system("/ericsson/security/bin/set_file_permissions.py> /ericsson/security/Test_Cases/granular.txt")
    with open('/ericsson/security/Test_Cases/granular.txt', 'r') as file1:
        if status in file1:
            print"SUCCESS"
            logging.info("Successfully executed set_file_permissions.py")
        else:
            print"FAIL"
            logging.info("Failed to exceute set_file_permissions.py")
    status = "**********SSH LOGIN BANNER is successfully configured with motd!*********\n"
    print"Executing set_motd_banner.py"
    os.system("/ericsson/security/bin/set_motd_banner.py > /ericsson/security/Test_Cases/granular.txt")
    with open('/ericsson/security/Test_Cases/granular.txt', 'r') as file1:
        if status in file1:
            print"SUCCESS"
            logging.info("Successfully executed set_motd_banner.py")
        else:
            print"FAIL"
            logging.info("Failed to exceute set_motd_banner.py")
    status = "**********Enforced SSH Protocol v2 for SSH communication on the server**********\n"
    print"Executing enable_ssh_proto_v2.py"
    os.system("/ericsson/security/bin/enable_ssh_proto_v2.py > /ericsson/security/Test_Cases/granular.txt")
    with open('/ericsson/security/Test_Cases/granular.txt', 'r') as file1:
        if status in file1:
            print"SUCCESS"
            logging.info("Successfully executed enable_ssh_proto_v2.py")
        else:
            print"FAIL"
            logging.info("Failed to exceute enable_ssh_proto_v2.py")
    status = "**********Successfully restricted user access and management for cron jobs**********\n"
    print"Executing restrict_cron.py"
    os.system("/ericsson/security/bin/restrict_cron.py > /ericsson/security/Test_Cases/granular.txt")
    with open('/ericsson/security/Test_Cases/granular.txt', 'r') as file1:
        if status in file1:
            print"SUCCESS"
            logging.info("Successfully executed restrict_cron.py")
        else:
            print"FAIL"
            logging.info("Failed to exceute restrict_cron.py")
    status = "**********SSH LOGIN BANNER is successfully configured with issue.net!*********\n"
    print"Executing set_ssh_banner.py"
    os.system("/ericsson/security/bin/set_ssh_banner.py > /ericsson/security/Test_Cases/granular.txt")
    with open('/ericsson/security/Test_Cases/granular.txt', 'r') as file1:
        if status in file1:
            print"SUCCESS"
            logging.info("Successfully executed set_ssh_banner.py")
        else:
            print"FAIL"
            logging.info("Failed to exceute set_ssh_banner.py")
    os.system("rm -rf /ericsson/security/Test_Cases/granular.txt > /dev/null 2>&1")

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_Granular_NH.log'
    pwd = '/ericsson/security/log/'
    os.system("mkdir -p "+pwd)

    format_string = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_string)

    print "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\x1b[32m\"Testing Granular NODE HARDENING\"\x1b[0m++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
    Granular_NH()
    pwd = '/ericsson/security/log/'
    print "Script logs are saved at : \033[93m"+pwd+"\033[00m directory!"
    
