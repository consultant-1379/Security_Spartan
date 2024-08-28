#!/usr/bin/python

"""This script verifies the type of server and opens the required tcp/udp ports based \
on the server type"""

import os
import subprocess
import logging
cmd = "firewall-cmd --list-ports"

def open_mws_ports():
    """This function enables the required tcp/udp ports on MWS servers"""

    logging.info('Enabling DNS port')
    os.system("firewall-cmd --zone=public --add-port=53/tcp --permanent > /dev/null 2>&1")

    logging.info('Enabling DHCP ports')
    os.system("firewall-cmd --zone=public --add-port=67/udp --permanent > /dev/null 2>&1")
    os.system("firewall-cmd --zone=public --add-port=68/udp --permanent > /dev/null 2>&1")

#   Removing tftp service and 69/udp as per JIRA EQEV-81041"""
    block_tftp_if_present()

#   Removing the deprecated ports('37726/tcp', '50740/udp') as per JIRA EQEV-86705"""
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
#    Removing the deprecated port 8080 as per EQEV-91804.
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
    #   '50720-50739/udp', '50740/udp') as per JIRA EQEV-86705
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

def configure_nh():
    """This function verifies the server type and opens the required ports based on that"""
    check_mount_point = os.path.ismount("/JUMP")
    flag = 0

    mws_insttype_path = os.path.exists("/ericsson/config/inst_type")
    eniq_insttype_path = os.path.exists("/eniq/installation/config/")

    se_status = subprocess.check_output("getenforce", shell=True)

    active_status = subprocess.check_output("systemctl status firewalld | grep -i Active \
| cut -d':' -f 2 | cut -d ' ' -f 2", shell=True)
    enabled_status = subprocess.check_output("systemctl status firewalld | sed -n '/Loaded:/p' \
| cut -d ';' -f 2 | cut -d ' ' -f 2", shell=True)

    if mws_insttype_path is True:
        mws_insttype = subprocess.check_output("cat /ericsson/config/inst_type", shell=True)
        server_config_name = subprocess.check_output("cat /ericsson/config/ericsson_use_config \
| cut -d'=' -f 2", shell=True)
        server_config_name = server_config_name.replace('\n', '')
        opening_mws_ports_msg = "\nOpening the required ports on the MWS server...\n"
        if check_mount_point is True and 'rhelonly' in mws_insttype and 'mws' \
in server_config_name:
            if se_status == 'Enforcing\n':
                print "\nSELinux is already in enforcing mode!\n"
                logging.info('SELinux is already in enforcing mode\n')
            else:
                os.system("/ericsson/security/bin/enforce_selinux.py > \
/ericsson/security/bin/log.txt")
                sestatus = subprocess.check_output("cat /ericsson/security/bin/log.txt \
| sed '4!d' | cut -d' ' -f 2", shell=True)
                if sestatus == 'enforced\n':
                    print "\nSELinux has been enforced successfully!!!\n"
                    logging.info("Successfully enforced SELinux")
                else:
                    logging.error("Failed to enforce SELinux.Exiting. . .\n")
                    print "\nFailed to enforce SELinux.Exiting. . .\n"
                    cleanup_on_exit()
                    exit()

            if active_status == "active\n" and enabled_status == "enabled\n":
                print "\nfirewalld service is already active and enabled!\n"
                logging.info('firewalld service is already active and enabled!\n')

                ports_enable_status = verify_firewalld_ports("MWS")
                if ports_enable_status == "True":
                    print "\nAll the required ports are already opened on the MWS server!\n"
                    logging.info('Required ports are already opened on the MWS server\n')
                    cleanup_on_exit()
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
service**********') or rec.startswith('**********Successfully started firewalld \
service**********') or rec.startswith('**********Successfully enabled firewalld \
service**********'):
                        print "\nfirewalld service has been enabled successfully!!!\n"
                        logging.info("Successfully enabled firewalld service\n")
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
        if se_status == 'Enforcing\n':
            print "\nSELinux is already in enforcing mode!\n"
            logging.info('SELinux is already in enforcing mode\n')
        else:
            os.system("/ericsson/security/bin/enforce_selinux.py > /ericsson/security/bin/log.txt")
            sestatus = subprocess.check_output("cat /ericsson/security/bin/log.txt | sed '4!d' \
| cut -d' ' -f 2", shell=True)
            if sestatus == 'enforced\n':
                print "\nSELinux has been enforced successfully!!!\n"
                logging.info("Successfully enforced SELinux\n")
            else:
                logging.error("Failed to enforce SELinux. Exiting. . .\n")
                print "\nFailed to enforce SELinux. Exiting. . .\n"
                cleanup_on_exit()
                exit()

        if active_status == "active\n" and enabled_status == "enabled\n":
            print "\nfirewalld service is already active and enabled!\n"
            logging.info('firewalld service is already active and enabled!\n')

            ports_enable_status = verify_firewalld_ports("ENIQ")
            if ports_enable_status == "True":
                print "\nAll the required ports are already opened on the ENIQ server!\n"
                logging.info('Required ports are already opened on the ENIQ server\n')
                cleanup_on_exit()
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
        print "\nSuccessfully opened the required ports on the %s server!\n" % server_type
        logging.info('Successfully opened the required ports on the %s server!\n' % server_type)
        cleanup_on_exit()
    else:
        print "\nFailed to open the required ports on the %s server. Exiting. . . \n" % server_type
        logging.error('Failed to open the required ports on the %s server. \
Exiting. . . \n' % server_type)
        cleanup_on_exit()
        exit()

def block_tftp_if_present():
    """This function is to block the tftp port"""
    open_ports = subprocess.check_output(cmd, shell=True)
    open_ports = list(open_ports.split(" "))
    open_ports[-1] = open_ports[-1].strip()
    status_bool1 = subprocess.check_output("getsebool tftp_home_dir  | cut -d'>' -f 2 ", shell=True)
    status_bool2 = subprocess.check_output("getsebool tftp_anon_write  \
| cut -d'>' -f 2 ", shell=True)

    if '69/udp' in open_ports:
        os.system("firewall-cmd --zone=public --remove-port=69/udp --permanent > /dev/null 2>&1")
        os.system("firewall-cmd --zone=public --remove-service=tftp --permanent > /dev/null 2>&1")
        restart_firewalld()
        logging.info('\nSucessfully removed 69/udp')

    if status_bool1 == " on\n":
        os.system("setsebool -P tftp_home_dir 0 > /dev/null 2>&1")
    if status_bool2 == " on\n":
        os.system("setsebool -P tftp_anon_write 0 > /dev/null 2>&1")

def verify_firewalld_ports(server_type):
    """This function is to verify the firewalld ports on MWS and ENIQ-S"""
    mws_ports = ['53/tcp', '67/udp', '68/udp', '2049/tcp', '2049/udp', '20048/tcp', '20048/udp',\
 '111/tcp', '111/udp', '1556/tcp', '13724/tcp', '13782/tcp']
    eniq_ports = ['6389/tcp', '2640/tcp', '2641/tcp', '2642/tcp', '8443/tcp', '2637/tcp',\
 '2638/tcp', '2639/tcp', '1200/tcp', '60001/tcp', '60002/tcp', '60003/tcp', '60004/tcp',\
 '60005/tcp', '1556/tcp', '13724/tcp', '13782/tcp', '4051-4100/tcp']

    list_ports = subprocess.check_output(cmd, shell=True)
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

def remove_deprecated_ports_if_present(server_type):
    """This function is to remove deprecated ports present on MWS and ENIQ-s"""
    mws_ports_rlist = ['37726/tcp', '50740/udp']
    eniq_ports_rlist = ['37726/tcp', '57006/tcp', '162/udp', '161/udp', '50720-50739/udp',\
 '50740/udp', '8080/tcp']

    list_ports = subprocess.check_output(cmd, shell=True)
    list_ports = list(list_ports.split(" "))
    list_ports[-1] = list_ports[-1].strip()
    port_flag1 = 0

    if server_type == "MWS":
        ports = mws_ports_rlist
    elif server_type == "ENIQ":
        ports = eniq_ports_rlist

    for i in ports:
        if i in list_ports:
            os.system("firewall-cmd --zone=public --remove-port=%s --permanent > \
/dev/null 2>&1" % i)
            logging.info("Successfully removed the port : %s" % i)
            port_flag1 = 1

    if port_flag1 == 1:
        restart_firewalld()

if __name__ == '__main__':
#    configure_nh()
    print "\n\033[93mWARNING : \033[00m This Script is not supported to be executed manually, \
for more details refer to ENIQ Node Hardening SAG...\n"
