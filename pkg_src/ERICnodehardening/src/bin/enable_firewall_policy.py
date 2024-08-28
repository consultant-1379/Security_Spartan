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
#
# ********************************************************************
# Name      : enable_firewall_policy.py
# Author    : ZTXXUPA
# Date      : 30-03-2020
# Revision  : A
# Purpose   : This script will enable the required firewall configurations(ports/services/protocols)
#             at system level using firewalld service. The supported systems are ENIQ-S and
#             MWS server.
# Reason    : EQEV-72609
#---------------------------------------------------------------------
"""

import os
import time
import subprocess
import logging
from Verify_NH_Config import block_tftp_if_present
from Verify_NH_Config import remove_deprecated_ports_if_present
from user_verification import user_verification

def open_mws_ports():
    """This function enables the required tcp/udp ports on MWS servers"""

    logging.info('Enabling DNS port')
    os.system("firewall-cmd --zone=public --add-port=53/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling DHCP ports')
    os.system("firewall-cmd --zone=public --add-port=67/udp --permanent > /dev/null 2>&1")
    os.system("firewall-cmd --zone=public --add-port=68/udp --permanent > /dev/null 2>&1")

#   Removing tftp service and 69/udp as per JIRA EQEV-81041
    block_tftp_if_present()

#   Removing the deprecated ports('37726/tcp', '50740/udp') as per JIRA EQEV-86705
    remove_deprecated_ports_if_present("MWS")

    logging.info('Enabling nfs ports')
    os.system("firewall-cmd --zone=public --add-port=2049/tcp --permanent > /dev/null 2>&1")
    os.system("firewall-cmd --zone=public --add-port=2049/udp --permanent > /dev/null 2>&1")

    logging.info('Enabling rpc.mountd port')
    os.system("firewall-cmd --zone=public --add-port=20048/tcp --permanent > /dev/null 2>&1")
    os.system("firewall-cmd --zone=public --add-port=20048/udp --permanent > /dev/null 2>&1")

    logging.info('Enabling mountd service')
    os.system("firewall-cmd --add-service=mountd --zone=internal --permanent > /dev/null 2>&1")

    logging.info('Enabling the port for rpcbind')
    os.system("firewall-cmd --zone=public --add-port=111/tcp --permanent > /dev/null 2>&1")
    os.system("firewall-cmd --zone=public --add-port=111/udp --permanent > /dev/null 2>&1")

    logging.info('Enabling rw for NFS export')
    os.system("setsebool -P nfs_export_all_rw 1")

    logging.info('Enabling VERITAS_PBX port')
    os.system("firewall-cmd --zone=public --add-port=1556/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling VNETD port')
    os.system("firewall-cmd --zone=public --add-port=13724/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling BPCD port')
    os.system("firewall-cmd --zone=public --add-port=13782/tcp --permanent > /dev/null 2>&1")

    restart_firewalld()


def open_eniq_ports():
    """This function enables all the required tcp/udp ports on ENIQ servers"""

    logging.info('Enabling Bulk CLI port')
    os.system("firewall-cmd --zone=public --add-port=6389/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling dwhdb port')
    os.system("firewall-cmd --zone=public --add-port=2640/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling etlrep port')
    os.system("firewall-cmd --zone=public --add-port=2641/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling multiblade dwh reader port')
    os.system("firewall-cmd --zone=public --add-port=2642/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling admin-ui ports')
#    Removing the deprecated port 8080 as per EQEV-91804
#    os.system("firewall-cmd --zone=public --add-port=8080/tcp --permanent > /dev/null 2>&1")
    os.system("firewall-cmd --zone=public --add-port=8443/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling repdb validation port')
    os.system("firewall-cmd --zone=public --add-port=2637/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling DB UtilServerPort port')
    os.system("firewall-cmd --zone=public --add-port=2638/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling dwhutil Server port')
    os.system("firewall-cmd --zone=public --add-port=2639/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling rmi port')
    os.system("firewall-cmd --zone=public --add-port=1200/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling licmgr port')
    os.system("firewall-cmd --zone=public --add-port=60001/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling scheduler port')
    os.system("firewall-cmd --zone=public --add-port=60002/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling engine port')
    os.system("firewall-cmd --zone=public --add-port=60003/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling lwphelper port')
    os.system("firewall-cmd --zone=public --add-port=60004/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling fls port')
    os.system("firewall-cmd --zone=public --add-port=60005/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling VERITAS_PBX port')
    os.system("firewall-cmd --zone=public --add-port=1556/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling VNETD port')
    os.system("firewall-cmd --zone=public --add-port=13724/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling BPCD port')
    os.system("firewall-cmd --zone=public --add-port=13782/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling nfs service')
    os.system("firewall-cmd --permanent --add-service=nfs > /dev/null 2>&1")

    logging.info('Enabling mountd service')
    os.system("firewall-cmd --permanent --add-service=mountd > /dev/null 2>&1")

    logging.info('Enabling the service for rpcbind')
    os.system("firewall-cmd --permanent --add-service=rpc-bind > /dev/null 2>&1")

    logging.info('Enabling kdump gui debug feature')
    os.system("setsebool -P kdumpgui_run_bootloader 1")

    logging.info('Enabling remote NFS server for the home directories')
    os.system("setsebool -P use_nfs_home_dirs on")

    logging.info('Enabling SO-EM port')
    os.system("firewall-cmd --zone=public --add-port=4051-4100/tcp --permanent > /dev/null 2>&1")

#   Removing the deprecated ports('37726/tcp', '57006/tcp', '162/udp', '161/udp', \
#    '50720-50739/udp', '50740/udp') as per JIRA EQEV-86705
    remove_deprecated_ports_if_present("ENIQ")

    restart_firewalld()

def restart_firewalld():
    """This function is to restart firewalld service"""
    logging.info('Reloading firewalld service')
    os.system("firewall-cmd --reload > /dev/null 2>&1")

def cleanup_on_exit():
    """This function defines clean up on exit"""
    os.system("rm -rf /ericsson/security/bin/*.pyc")
    os.system("rm -rf /ericsson/security/bin/*.txt")

def display_open_ports():
    """This function is to display the open ports"""
    disp = raw_input("\033[93m\"Do you wish to view the list of open firewalld \
ports(y/n):?\"\033[00m ")

    exit_msg = "\x1b[32mExiting the script. . .\x1b[0m\n"

    if (disp == 'y') or (disp == 'Y'):
        list_ports = subprocess.check_output("firewall-cmd --list-ports", shell=True)
        list_ports = list(list_ports.split(" "))
        list_ports[-1] = list_ports[-1].strip()
        dash = '-' * 40
        print "\n"

        for i in range(len(list_ports)):
            if i == 0:
                print dash
                print('{:<10s}'.format('List of open Ports'))
                print dash
            else:
                print('{:<10s}'.format(list_ports[i]))
        print "\n"
        print exit_msg
        cleanup_on_exit()
    elif (disp == 'n') or (disp == 'N'):
        print"\n"
        print exit_msg
        cleanup_on_exit()
    else:
        print "Invalid Option\n"
        print exit_msg
        cleanup_on_exit()

def configure_nh():
    """This function verifies the server type and opens the required ports based on that"""
    check_mount_point = os.path.ismount("/JUMP")
    flag = 0

    mws_insttype_path = os.path.exists("/ericsson/config/inst_type")
    eniq_insttype_path = os.path.exists("/eniq/installation/config/")
    active_status = subprocess.check_output("systemctl status firewalld | grep -i Active \
| cut -d':' -f 2 | cut -d ' ' -f 2", shell=True)
    enabled_status = subprocess.check_output("systemctl status firewalld | sed -n '/Loaded:/p' \
| cut -d ';' -f 2 | cut -d ' ' -f 2", shell=True)

    opening_mws_ports_msg = "\nOpening the required ports on the MWS server...\n"
    if mws_insttype_path is True:
        mws_insttype = subprocess.check_output("cat /ericsson/config/inst_type", shell=True)
        server_config_name = subprocess.check_output("cat /ericsson/config/ericsson_use_config \
| cut -d'=' -f 2", shell=True)
        server_config_name = server_config_name.replace('\n', '')

        if check_mount_point is True and 'rhelonly' in mws_insttype and 'mws' in server_config_name:
            if active_status == "active\n" and enabled_status == "enabled\n":
                print "\nfirewalld service is already active and enabled!\n"
                logging.info('firewalld service is already active and enabled!\n')

                ports_enable_status = verify_firewalld_ports("MWS")
                if ports_enable_status == "True":
                    print "\nAll the required ports are already opened on the MWS server!\n"
                    logging.info('Required ports are already opened on the MWS server\n')
                    display_open_ports()
                elif ports_enable_status == "False":
                    print opening_mws_ports_msg
                    logging.info(opening_mws_ports_msg)
                    open_mws_ports()
                    verify_port_status("MWS")
            else:
                os.system("/ericsson/security/bin/enable_firewall.py > \
/ericsson/security/bin/log.txt")
                for line in open("/ericsson/security/bin/log.txt", "r"):
                    rec = line.strip()
                    if rec.startswith('**********Successfully started and enabled firewalld \
service**********') or rec.startswith('**********Successfully started firewalld service\
**********') or rec.startswith('**********Successfully enabled firewalld service**********'):
                        print "\nfirewalld service has been enabled successfully!!!\n"
                        logging.info("Successfully enabled firewalld service")
                        flag = 1
                if flag != 1:
                    print "\nFailed to enable firewalld service. Exiting. . .\n"
                    logging.error("\nFailed to enable firewalld service. Exiting. . .\n")
                    cleanup_on_exit()
                    exit()
                print opening_mws_ports_msg
                logging.info(opening_mws_ports_msg)
                open_mws_ports()
                verify_port_status("MWS")
        else:
            print "\nMWS configuration is not complete.Please verify the configuration!\n"
            logging.error('MWS configuration is not complete.Please verify the configuration!')
            logging.info("\n")
            cleanup_on_exit()
            exit()
    elif eniq_insttype_path is True:
        opening_eniq_ports_msg = "\nOpening the required ports on the ENIQ server...\n"
        if active_status == "active\n" and enabled_status == "enabled\n":
            print "\nfirewalld service is already active and enabled!\n"
            logging.info('firewalld service is already active and enabled!\n')

            ports_enable_status = verify_firewalld_ports("ENIQ")
            if ports_enable_status == "True":
                print "\nAll the required ports are already opened on the ENIQ server!\n"
                logging.info('Required ports are already opened on the ENIQ server\n')
                display_open_ports()
            elif ports_enable_status == "False":
                print opening_eniq_ports_msg
                logging.info(opening_eniq_ports_msg)
                open_eniq_ports()
                verify_port_status("ENIQ")
        else:
            os.system("/ericsson/security/bin/enable_firewall.py > /ericsson/security/bin/log.txt")
            for line in open("/ericsson/security/bin/log.txt", "r"):
                rec = line.strip()
                if rec.startswith('**********Successfully started and enabled firewalld \
service**********') or rec.startswith('**********Successfully started firewalld \
service**********') or rec.startswith('**********Successfully enabled firewalld \
service**********'):
                    print "\nfirewalld service has been enabled successfully!!!\n"
                    logging.info("Successfully enabled firewalld service\n")
                    flag = 1
            if flag != 1:
                print "\nFailed to enable firewalld service!!!\n"
                logging.error("\nFailed to enable firewalld service!!!\n")
                cleanup_on_exit()
                exit()
            print opening_eniq_ports_msg
            logging.info(opening_eniq_ports_msg)
            open_eniq_ports()
            verify_port_status("ENIQ")
    else:
        print "\nServer not configured either as MWS nor as Eniq\n"
        logging.error('Server not configured either as MWS nor as Eniq')
        cleanup_on_exit()
        exit()

def verify_port_status(server_type):
    """This function is to verify the port status on MWS and ENIQ-S"""
    if server_type == "MWS":
        port_status = verify_firewalld_ports("MWS")
    elif server_type == "ENIQ":
        port_status = verify_firewalld_ports("ENIQ")

    if port_status == "True":
        print "\nSuccessfully opened the required ports on the %s server.\n" % server_type
        logging.info('Successfully opened the required ports on the %s server.\n' % server_type)
        display_open_ports()
    else:
        print "\nFailed to open the required ports on the %s server.\n" % server_type
        logging.error('Failed to open the required ports on the %s server.\n' % server_type)
        display_open_ports()

def verify_firewalld_ports(server_type):
    """This function is to verify the firewalld ports on MWS and ENIQ-S"""
    mws_ports = ['53/tcp', '67/udp', '68/udp', '2049/tcp', '2049/udp', '20048/tcp', '20048/udp',\
 '111/tcp', '111/udp', '1556/tcp', '13724/tcp', '13782/tcp']

    eniq_ports = ['6389/tcp', '2640/tcp', '2641/tcp', '2642/tcp', '8443/tcp', '2637/tcp', \
'2638/tcp', '2639/tcp', '1200/tcp', '60001/tcp', '60002/tcp', '60003/tcp', '60004/tcp', \
'60005/tcp', '1556/tcp', '13724/tcp', '13782/tcp', '4051-4100/tcp']

    list_ports = subprocess.check_output("firewall-cmd --list-ports", shell=True)
    list_ports = list(list_ports.split(" "))
    list_ports[-1] = list_ports[-1].strip()
    port_flag = 0

    if server_type == "MWS":
        block_tftp_if_present()
        remove_deprecated_ports_if_present("MWS")
        ports = mws_ports
    elif server_type == "ENIQ":
        remove_deprecated_ports_if_present("ENIQ")
        ports = eniq_ports

    for i in ports:
        if i not in list_ports:
            port_flag = 1

    if port_flag == 0:
        return "True"
    else:
        return "False"

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + 'enable_firewall_policy.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % fname,
                        format=format_str)
    configure_nh()
    print "Script logs are saved at : \033[93m/ericsson/security/log/Apply_NH_Logs/\
Manual_Exec/\033[00m directory!"
