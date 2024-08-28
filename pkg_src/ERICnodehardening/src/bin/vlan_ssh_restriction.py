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
# *********************************************************************
# Name      : vlan_ssh_restriction.py
# Author    : XMEGHHR
# Date      : 10-01-2020
# Revision  : A
# Purpose   : This script is to enable VLAN SSH restriction and
#             to allow IP's in the IP list.
# Reason    : EQEV-68439
#----------------------------------------------------------------------
# History
"""
import os
import re
import logging
import time
import pickle
import signal
import subprocess
from user_verification import user_verification
VLAN_CFG = "/ericsson/security/config/SSH_VLAN_restriction.cfg"
WHITELIST_CFG = "/ericsson/security/config/IP_Whitelisting.cfg"
REG_255 = '(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'
REG_IPV6 = r'[0-9a-fA-F:]+:[0-9a-fA-F:]+:[0-9a-fA-F:]+:[0-9a-fA-F:]+'
COLORS = {'RED' : '\33[31m', 'END' : '\033[0m', 'GREEN' : '\33[32m', 'YELLOW' : '\33[33m'}
file_name = "vlan_ssh_restriction.py"
info = "[INFO]:  Cleaning up"
log_inf = "Cleaning up"
def log_func(script_name, state):
    """This function is to create log file header and footer"""
    if state == 0:
        open(LOG_PATH, 'a').writelines('*'*95+'\n')
        host = subprocess.check_output('hostname', shell=True).replace('\n', '')
        start_time = time.strftime("%Y-%m-%d_%H-%M-%S")
        open(LOG_PATH, 'a').writelines(host+' '*(95-len(host)-len(start_time))+start_time+'\n')
        open(LOG_PATH, 'a').writelines(script_name+'\n')
        open(LOG_PATH, 'a').writelines('*'*95+'\n')
    elif state == 1:
        open(LOG_PATH, 'a').writelines('*'*95+'\nLog file location:\n')
        open(LOG_PATH, 'a').writelines(LOG_PATH+'\n'+'*'*95+'\n')
        print "Script logs are saved at : \033[93m %s \033[00m" % LOG_PATH
def firewall_check():
    """This function is to check the firewalld status"""
    try:
        print "[INFO]:  Checking firewalld status"
        logging.info("Checking firewalld status")
        active_status = subprocess.check_output("systemctl status firewalld | grep -i Active | \
cut -d':' -f 2 | cut -d ' ' -f 2", shell=True)
        enabled_status = subprocess.check_output("systemctl status firewalld | \
sed -n '/Loaded:/p' | cut -d ';' -f 2 | cut -d ' ' -f 2", shell=True)
        if active_status == "active\n" and enabled_status == "enabled\n":
            print "[INFO]:  Firewalld status is active and enabled"
            logging.info("Firewalld status is active and enabled")
            return True
        logging.info("Firewalld not enables")
        print COLORS['RED']+"[ERROR]: firewalld is not enabled. Make sure Node hardening is "+ \
"applied on the server.\nRefer ENIQ-S Node Hardening Guide"+ \
"(4/1543-CNA 403 2613) for Nodehardening Procedure" +COLORS['END']
        return False
    except (subprocess.CalledProcessError, UnicodeDecodeError, AttributeError, OSError, \
ValueError) as e:
        logging.warning("Error occured while fetching firewall status : %s", e)

def vlan_restriction():
    """This function will validate the subnet IPs format and save the firewalld rules in a file"""
    try:
        if not os.path.exists(VLAN_CFG):
            logging.error("%s%s file not found%s", COLORS['RED'], VLAN_CFG, COLORS['END'])
            print COLORS['RED'] + "[ERROR]:" + COLORS['END'] + "%s file not found" % VLAN_CFG + \
COLORS['END']
            log_func(file_name, 1)
            exit(1)

        check_ipv4_subnet = ('^' + REG_255 + r'\.' + REG_255 + r'\.' + REG_255 + r'\.' + \
REG_255 + r'[/]([0-2]?[0-9]|3[0 1])$')

        check_ipv6_subnet = r'^[0-9a-fA-F:]+:[0-9a-fA-F:]+/[0-9]+$'

        valid_subnet, invalid_subnet = list(), list()
        os.system('> /ericsson/security/config/Vlan_rules.cfg')
        os.system('> /ericsson/security/config/Permanent_Vlan_rules.cfg')

        print "[INFO]:  Input validation is in progress for SSH VLAN restriction"
        logging.info("Input validation is in progress for SSH VLAN restriction")

        for subnet in open(VLAN_CFG, "r").read().splitlines():
            if not subnet or subnet[0] == '#':
                continue
            elif bool(re.match(check_ipv4_subnet, subnet)) or bool(re.match(check_ipv6_subnet, subnet)):
                valid_subnet.append(subnet)
            else:
                invalid_subnet.append(subnet)

        if invalid_subnet:
            log_space = '\n' + ' ' * 32
            print_space = '\n' + ' ' * 9
            invalids = log_space.join(invalid_subnet)
            print COLORS['RED'] + "[ERROR]: Invalid subnet entries found:%s" % \
print_space + print_space.join(invalid_subnet) + \
print_space + "Correct the entries in %s file" % VLAN_CFG + COLORS['END']

            logging.error('%sInvalid subnet entries found:%s%s%s', \
            COLORS['RED'], log_space, invalids, COLORS['END'])
            print info
            logging.info(log_inf)
            os.system("rm -rf /ericsson/security/config/Permanent_Vlan_rules.cfg " + \
"/ericsson/security/config/Vlan_rules.cfg")
            log_func(file_name, 1)
            exit(1)

        if not valid_subnet and not invalid_subnet:
            logging.error("%s%s has no  subnet entries%s", COLORS['RED'], VLAN_CFG, COLORS['END'])
            print COLORS['RED'] + "[ERROR]: %s do not have any subnet entries." % VLAN_CFG + \
" Script exiting" + COLORS['END']
            print info
            logging.info(log_inf)
            os.system("rm -rf /ericsson/security/config/Permanent_Vlan_rules.cfg " + \
"/ericsson/security/config/Vlan_rules.cfg")
            log_func(file_name, 1)
            exit(1)

        for subnet in valid_subnet:
            cmd_ipv4 = ("firewall-cmd --zone=public --add-rich-rule 'rule family=ipv4 " + \
"source address=\"%s\" service name=\"ssh\" accept'\n" % subnet)
            cmd_ipv6 = ("firewall-cmd --zone=public --add-rich-rule 'rule family=ipv6 " + \
"source address=\"%s\" service name=\"ssh\" accept'\n" % subnet)

            pcmd_ipv4 = ("firewall-cmd --zone=public --add-rich-rule 'rule family=ipv4 " + \
"source address=\"%s\" service name=\"ssh\" accept' --permanent\n" % subnet)
            pcmd_ipv6 = ("firewall-cmd --zone=public --add-rich-rule 'rule family=ipv6 " + \
"source address=\"%s\" service name=\"ssh\" accept' --permanent\n" % subnet)

            is_ipv4 = bool(re.match(check_ipv4_subnet, subnet))
            is_ipv6 = bool(re.match(check_ipv6_subnet, subnet))

            if is_ipv4 == True:
                open('/ericsson/security/config/Vlan_rules.cfg', 'a').write(cmd_ipv4)
                open('/ericsson/security/config/Permanent_Vlan_rules.cfg', 'a').write(pcmd_ipv4)
                logging.info("Firewalld rules written in Config file for %s", subnet)
            elif is_ipv6 == True:
                open('/ericsson/security/config/Vlan_rules.cfg', 'a').write(cmd_ipv6)
                open('/ericsson/security/config/Permanent_Vlan_rules.cfg', 'a').write(pcmd_ipv6)
                logging.info("Firewalld rules written in Config file for %s", subnet)
    except (subprocess.CalledProcessError, IOError, AttributeError, OSError, \
ValueError) as e:
        logging.warning("Error while allowing Permanent IP : %s", e)

def white_listing():
    """This function will validate the IPs format and save the firewalld rules in a file"""
    try:
        if not os.path.exists(WHITELIST_CFG):
            logging.error(COLORS['RED'] + "%s file not found" % WHITELIST_CFG + COLORS['END'])
            print COLORS['RED'] + "[ERROR]: %s not Found. exiting" % WHITELIST_CFG + COLORS['END']
            log_func(file_name, 1)
            exit(1)

        check_ipv4_ip = '^' + REG_255 + r'\.' + REG_255 + r'\.' + REG_255 + r'\.' + REG_255 + '$'
        check_ipv6_ip = r'^[0-9a-fA-F:]+:[0-9a-fA-F:]+$'

        valid_ip, invalid_ip = list(), list()
        os.system('> /ericsson/security/config/white_list_rules.cfg')
        os.system('> /ericsson/security/config/Permanent_white_list_rules.cfg')

        print "[INFO]:  Input validation is in progress for allowing IP"
        logging.info("Input validation is in progress for allowing IP")

        for ip_list in open(WHITELIST_CFG, "r").read().splitlines():
            if not ip_list or ip_list[0] == '#':
                continue
            elif bool(re.match(check_ipv4_ip, ip_list)) or bool(re.match(check_ipv6_ip, ip_list)):
                valid_ip.append(ip_list)
            else:
                invalid_ip.append(ip_list)

        if invalid_ip:
            log_space = '\n' + ' ' * 32
            print_space = '\n' + ' ' * 9
            invalidi = log_space.join(invalid_ip)
            print COLORS['RED'] + "[ERROR]: Invalid IP entries found:%s" % \
                print_space + print_space.join(invalid_ip) + \
                print_space + "Correct the entry in %s file" % WHITELIST_CFG + COLORS['END']

            logging.error(COLORS['RED'] + "Invalid IP entries found:" + log_space + \
"%s", invalidi + COLORS['END'])
            print info
            logging.info(log_inf)
            os.system("rm -rf /ericsson/security/config/white_list_rules.cfg " + \
"/ericsson/security/config/Permanent_white_list_rules.cfg" + \
" /ericsson/security/BACKUP_CONFIG_FILES/Rollback_IP_white_list_rules.cfg")
            log_func(file_name, 1)
            exit(1)

        if not valid_ip and not invalid_ip:
            logging.error(COLORS['RED'] + "%s do not have any IP entries." % \
WHITELIST_CFG + COLORS['END'])
            print COLORS['RED']+"[ERROR]: %s not Found. exiting" % (WHITELIST_CFG,) + COLORS['END']

            print info
            logging.info(log_inf)
            os.system("rm -rf /ericsson/security/config/white_list_rules.cfg " + \
"/ericsson/security/config/Permanent_white_list_rules.cfg ")
            log_func(file_name, 1)
            exit(1)

        for ip_list in valid_ip:
            cmd_ipv4 = ("firewall-cmd --zone=public --add-rich-rule 'rule family=ipv4 source " + \
"address=\"%s\" service name=\"ssh\" accept'\n" % ip_list)
            cmd_ipv6 = ("firewall-cmd --zone=public --add-rich-rule 'rule family=ipv6 source " + \
"address=\"%s\" service name=\"ssh\" accept'\n" % ip_list)
            pcmd_ipv4 = ("firewall-cmd --zone=public --add-rich-rule 'rule family=ipv4 source " + \
"address=\"%s\" service name=\"ssh\" accept' --permanent\n" % ip_list)
            pcmd_ipv6 = ("firewall-cmd --zone=public --add-rich-rule 'rule family=ipv6 source " + \
"address=\"%s\" service name=\"ssh\" accept' --permanent\n" % ip_list)
            is_ipv4 = bool(re.match(check_ipv4_ip, ip_list))
            is_ipv6 = bool(re.match(check_ipv6_ip, ip_list))
            if is_ipv4 == True:
                open('/ericsson/security/config/white_list_rules.cfg', 'a').write(cmd_ipv4)
                open('/ericsson/security/config/Permanent_white_list_rules.cfg', 'a').\
write(pcmd_ipv4)
                logging.info("Firewalld rules written in Config file for %s", ip_list)

            elif is_ipv6 == True:
                open('/ericsson/security/config/white_list_rules.cfg', 'a').write(cmd_ipv6)
                open('/ericsson/security/config/Permanent_white_list_rules.cfg', 'a').\
write(pcmd_ipv6)
                logging.info("Firewalld rules written in white_list_rules.cfg for %s", ip_list)
    except (subprocess.CalledProcessError, IOError, AttributeError, OSError, \
ValueError) as e:
        logging.warning("Error while writing firewall rules to the file : %s", e)

def apply_white_list():
    """This function is to allow the provided IPs on the server"""
    try:
        print "[INFO]:  Performing allowing IP's on the server"
        ipv4_pattern = REG_255 + r'\.' + REG_255 + r'\.' + REG_255 + r'\.' + REG_255
        ipv6_pattern = REG_IPV6
        find_ip = r'(' + ipv4_pattern + r')|(' + ipv6_pattern + r')'

        for command in open('/ericsson/security/config/white_list_rules.cfg', "r").read().splitlines():
            if command:
                whitelist_ip = re.search(find_ip, command).group(0)
                status = os.system("{} >/dev/null 2>&1".format(command)) if os.name == "posix" \
else os.system("{} >NUL 2>&1".format(command))
                if status != 0:
                    print COLORS['RED'] + "[ERROR]: Failed to allow IP %s, " % whitelist_ip + \
"check %s for further details" % LOG_PATH + COLORS['END']
                    logging.error(COLORS['RED'] + "Failed to allow IP %s, check %s for further details" \
+ COLORS['END'], whitelist_ip, LOG_PATH)
                    print info
                    logging.info(log_inf)
                    os.system("rm -rf /ericsson/security/config/white_list_rules.cfg" + \
" /ericsson/security/config/Permanent_white_list_rules.cfg ")
                    os.system("systemctl restart firewalld" + " 1>/dev/null 2>&1")
                    log_func(file_name, 1)
                    exit(1)
                logging.info("Whitelisted IP is %s", whitelist_ip)
        print "[INFO]:  Allowing IP's on the server is successful for the provided IPs"
        logging.info("Allowing IP's on the server is successful for the provided IPs")
    except (subprocess.CalledProcessError, IOError, AttributeError, OSError, \
ValueError) as e:
        logging.warning("Error while Whitelisting passed IP address : %s", e)

def apply_vlan():
    """This function is to perform SSH VLAN restriction for provided the provided subnet IPs"""
    try:
        print "[INFO]:  Performing VLAN Restriction on the server"
        ipv4_pattern = REG_255 + r'\.' + REG_255 + r'\.' + REG_255 + r'\.' + REG_255
        ipv6_pattern = REG_IPV6
        ipv4_subnet_pattern = ipv4_pattern + r'[/](3[0-2]|[0-2]?[0-9])'
        ipv6_subnet_pattern = ipv6_pattern + r'[/](12[0-8]|1[0-1][0-9]|[0-9]?[0-9])'
        find_subnet = r'(' + ipv4_subnet_pattern + r')|(' + ipv6_subnet_pattern + r')'

        for command in open('/ericsson/security/config/Vlan_rules.cfg', "r").read().splitlines():
            if command:
                status = os.system("{} >/dev/null 2>&1".format(command)) if os.name == "posix" \
else os.system("{} >NUL 2>&1".format(command))
                vlan_subnet = re.search(find_subnet, command).group(0)
                if status != 0:
                    print COLORS['RED'] + "[ERROR]: Failed to restrict SSH VLAN for %s," % \
vlan_subnet + "check %s for further details" % LOG_PATH + COLORS['END']
                    logging.error(COLORS['RED'] + "Failed to restrict SSH VLAN for %s, check" \
% vlan_subnet + " %s for further details %s", LOG_PATH, COLORS['END'])
                    print info
                    logging.info(log_inf)
                    os.system("rm -rf /ericsson/security/config/Permanent_Vlan_rules.cfg " + \
" /ericsson/security/config/Vlan_rules.cfg")
                    os.system("systemctl restart firewalld" + " 1> /dev/null 2>&1")
                    log_func(file_name, 1)
                    exit(1)
                logging.info("SSH VLAN restricted for  %s", vlan_subnet)
        print "[INFO]:  Applied SSH VLAN Restriction for the provided subnets"
        logging.info("Applied SSH VLAN Restriction for the provided subnets")
    except (subprocess.CalledProcessError, IOError, AttributeError, OSError, \
ValueError) as e:
        logging.warning("Error while Restricting VLAN: %s", e)

if __name__ == '__main__':
    user_verification()
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    USER = subprocess.check_output("whoami", shell=True).replace('\n', '')
    if USER != 'root':
        print "\33[31mYou are not root user.\nScript exiting.\033[0m"
        exit(1)
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_VLAN_SSH_Restriction_temporary.log'
    os.system("mkdir -p /ericsson/security/log/VLAN_Logs")
    FORMAT_STR = '%(asctime)s\t%(levelname)s\t%(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/VLAN_Logs/%s" % FNAME,
                        format=FORMAT_STR)
    LOG_PATH = "/ericsson/security/log/VLAN_Logs/"+FNAME
    log_func(file_name, 0)
    MESSAGE1 = '#'*105+'\n'+ \
               "#  Make sure you have updated the following config files"+ \
               " SSH_VLAN_restriction.cfg IP_Whitelisting.cfg   #"+'\n'+'#'*105
    MESSAGE2 = '#'*105+'\n'+'#'+' '*14+ \
               "Verify if the SSH connections are working for the requested subnet and IPs."+ \
               ' '*14+'#'+'\n'+'#'+' '*5+ \
               "NOTE:Proceed with vlan_ssh_restriction_permanent.py only if the SSH connections "+ \
               "are successful"+' '*5+'#'+'\n'+'#'*105
    TMP_STATUS = False
    WHITELIST_STATUS = False
    print MESSAGE1
    CHOICE = raw_input("Does, Allowing IP's from the IP list is required (y/n):? ")
    if not firewall_check():
        log_func(file_name, 1)
        exit(1)
    if CHOICE == "y" or CHOICE == "Y":
        print "[INFO]:  Restarting firewalld service"
        logging.info("Restarting firewalld service")
        os.system("systemctl restart firewalld 1>/dev/null 2>&1")
        vlan_restriction()
        white_listing()
        print "[INFO]:  Removing SSH service from public zone"
        logging.info("Removing SSH service from public zone")
        os.system("firewall-cmd  --remove-service=ssh 1>/dev/null 2>&1")
        apply_white_list()
        apply_vlan()
        TMP_STATUS, WHITELIST_STATUS = True, True
        print info
        logging.info(log_inf)
        os.system("rm -rf /ericsson/security/config/Vlan_rules.cfg \
/ericsson/security/config/white_list_rules.cfg")
        print MESSAGE2
    elif (CHOICE == 'n') or (CHOICE == 'N'):
        print "[INFO]:  Restarting firewalld service"
        logging.info("Restarting firewalld service")
        os.system("systemctl restart firewalld 1>/dev/null 2>&1")
        vlan_restriction()
        print "[INFO]:  Removing SSH service from public zone"
        logging.info("Removing SSH service from public zone")
        os.system("firewall-cmd  --remove-service=ssh 1>/dev/null 2>&1")
        apply_vlan()
        TMP_STATUS = True
        print info
        logging.info(log_inf)
        os.system("rm -rf /ericsson/security/config/Vlan_rules.cfg")
        print MESSAGE2
    else:
        print COLORS['RED']+"\n[ERROR]: Choose valid option...!!\n"+COLORS['END']
        logging.error(COLORS['RED']+"\nChoose valid option...!!!"+COLORS['END'])
        exit(0)
    pickle.dump([TMP_STATUS, WHITELIST_STATUS], \
open('/ericsson/security/config/temp_flag.pkl', 'w'))
    log_func(file_name, 1)



