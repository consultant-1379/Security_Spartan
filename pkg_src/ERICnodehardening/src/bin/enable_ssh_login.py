#!/usr/bin/python
"""
# **********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# **********************************************************************
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
# **********************************************************************
# Name       : enable_ssh_login.py
# Purpose    : This script configures sshd_config file to secure ssh
#              access to users based on server types.
# Author     : Pradeep Kumar Doddagoudar (zdodpra)
# Config File: username
# Reason     : EQEV-89425
# **********************************************************************
"""
import os
import logging
import time
import subprocess
import socket
import re
import sys
from collections import OrderedDict
from IPy import IP
from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from sentinel_hardening import log_func
err_group = "Privileged user group not found"
def ssh_user(flag):
    """This function enables the restriction on ssh login access based on server type"""
    backup_files('/etc/ssh/sshd_config', [])
    try:
#        calling_script_name = inspect.stack()[1][1]
#        calling_func_name = inspect.stack()[1][3]
        flag_value = flag
        server = server_type()
        hostname = socket.gethostname()
        remove_user()
        if server == 'MWS':
            fetch_users = mws_access()
            status = add_users(fetch_users, server, hostname, flag_value)
            if status == 0:
                return 0
            else:
                ip_update_to_hostname()
                subprocess.check_output("sed -i '/^AllowUsers/ s/  */ /g' /etc/ssh/sshd_config", \
shell=True)
                return 1
        elif server == "ENIQ-S":
            fetch_users = eniq_access(hostname)
            status = add_users(fetch_users, server, hostname, flag_value)
            if status == 0:
                return 0
            else:
                ip_update_to_hostname()
                subprocess.check_output("sed -i '/^AllowUsers/ s/  */ /g' /etc/ssh/sshd_config", \
shell=True)
                return 1
        else:
            logging.info("Server is not configured either ENIQ-S or MWS")
            return 0
    except ValueError:
        print "\n\x1b[31mFound Invalid Hostname\x1b[0m\n"
        logging.info("Found Invalid Hostname")
        return 0
def server_type():
    """This function returns the server type"""
    check_mount_point = os.path.ismount("/JUMP")
    mws_insttype_path = os.path.exists("/ericsson/config/inst_type")
    eniq_insttype_path = os.path.exists("/eniq/installation/config/")
    if mws_insttype_path is True:
        mws_insttype = subprocess.check_output("cat /ericsson/config/inst_type", shell=True)
        server_config_name = subprocess.check_output("cat /ericsson/config/ericsson_use_config \
| cut -d'=' -f 2", shell=True)
        server_config_name = server_config_name.replace('\n', '')
        if (check_mount_point is True) and ('rhelonly' in mws_insttype) \
and ('mws' in server_config_name):
            logging.info("Server is configured as MWS")
            return 'MWS'
    elif eniq_insttype_path is True:
        logging.info("Server is configured as ENIQ-S")
        return "ENIQ-S"
    else:
        logging.error("Server is not configured either as ENIQ-S or MWS")
def mws_access():
    """This function fetches the required MWS users"""
    try:
        with open("/ericsson/security/bin/username", 'r') as fin:
            user_list = fin.readlines()
            fin.close()
        new_users = []
        for i in user_list:
            if i != '\n' and i != 'dcuser\n' and i != 'storadm\n':
                new_users.append(i)
        new_users = ''.join(new_users)
        new_users = new_users.strip()
        new_users = new_users.replace('\n', ' ')
        new_users = new_users.split(' ')
        return new_users
    except (IOError, RuntimeError, TypeError):
        logging.error("Cannot add users to allow SSH access list")
def eniq_access(hostname):
    """This function fetches the required ENIQ-S users"""
    try:
        with open("/ericsson/security/bin/username", 'r') as fin:
            user_list = fin.readlines()
            fin.close()
        new_users = []
        for i in user_list:
            if i != '\n':
                new_users.append(i)
        for index, value in enumerate(user_list):
            if value == "storadm\n":
                user_list[index] = value.replace('\n', '')+"@"+ hostname+"\n"
        new_users = ''.join(user_list)
        new_users = new_users.strip()
        new_users = new_users.replace('\n', ' ')
        new_users = new_users.split(' ')
        return new_users
    except (IOError, RuntimeError, TypeError, ValueError):
        logging.error("Provided Hostname is not valid, Exiting ...")
def add_users(users, server, hostname, flag_value):
    """This function adds the users to sshd_config file"""
    try:
        admin_users = ""
        if flag_value == 1:
            admin_users = add_admin_users()
            if err_group == admin_users:
                return 0
            else:
                users  = users + admin_users
        new_users = users
        with open("/etc/ssh/sshd_config", 'r') as fin:
            data = fin.readlines()
        data1 = []
        flag = 0
        a = 0
        existing_users = ""
        for line in data:
            if line != '\n':
                data1 = line.split()
                if data1[0] == "AllowUsers":
                    flag = 1
                    a = data.index(line)
                    existing_users = data[a]
                    existing_users = existing_users.split()
        if flag == 1:
            existing_users = check_existing_users(server, hostname, existing_users)
            root_hostname = "root@"+hostname
            dcuser_hostname = "dcuser@"+hostname
            for i in new_users:
                if i=="root" and root_hostname in existing_users:
                    new_users.remove("root")
                elif i=="dcuser" and dcuser_hostname in existing_users:
                    new_users.remove("dcuser")
            for i in new_users:
                if i not in existing_users:
                    existing_users += [i]
            existing_users = ' '.join(existing_users)
            data[a] = existing_users + '\n'
        if flag != 1:
            new_users = ' '.join(new_users)
            new_users = "AllowUsers"+" " + new_users+"\n"
            data = add_new_users(data, new_users)
        with open('/etc/ssh/sshd_config', 'w') as fout:
            fout.writelines(''.join(data))
        print "\n**********SSH access has been enabled for the all user accounts**********\n"
        logging.info('SSH access has been enabled for the all user accounts')
        if flag_value != 1:
            print "\nRestarting the SSHD service. . . . . . .\n"
            logging.info('Restarting the SSHD service')
            os.system("systemctl restart sshd")
    except Exception as e:
        print e
#    except (IOError, RuntimeError, AttributeError, TypeError):
#        logging.error("Failed to allow SSH access to the users")
def remove_user():
    try:
        with open("/etc/ssh/sshd_config", 'r') as fin:
            data = fin.readlines()
        remove_user=["dcdata", "storobs"]
        hostname = socket.gethostname()
        data1 = []
        a = 0
        existing_users = ""
        for line in data:
            if line != '\n':
                data1 = line.split()
                if data1[0] == "AllowUsers":
                    a = data.index(line)
                    existing_users = data[a]
                    existing_users = existing_users.split()
                    for i in remove_user:
                        user1=i+"@"+hostname
                        if user1 in existing_users:
                            cmd = "sed -i -e '/AllowUsers/s/"+user1+"//' /etc/ssh/sshd_config"
                            os.system(cmd)
    except (IOError, RuntimeError, AttributeError, TypeError):
        logging.error("Failed to allow SSH access to the users")
def add_new_users(data, new_users):
    """This will add the parameter AllowUsers to allow ssh access for users in sshd_config file"""
    try:
        data2 = []
        for i in data:
            if i != '\n':
                data2 = i.split()
                if data2[0] == "UsePAM":
                    p = data.index(i)
                    data[p] = data[p]+new_users
        return data
    except (IOError, RuntimeError, AttributeError, TypeError):
        logging.error("Failed to add users into SSH access list")
def check_existing_users(server, hostname, existing_users):
    """This function checks and updates the existing users according to the server type"""
    try:
        if server == 'ENIQ-S':
            for index, value in enumerate(existing_users):
                if value == "storadm":
                    existing_users[index] = value+"@"+ hostname
        elif server == 'MWS':
            for index, value in enumerate(existing_users):
                unwanted_users = ['storadm', 'dcuser']
                existing_users = [item for item in existing_users if item not in unwanted_users]
        return existing_users
    except (IOError, RuntimeError, AttributeError, TypeError):
        logging.error("Failed to fetch existing users")
def add_admin_users():
    group = subprocess.check_output("cat /etc/group",shell=True)
    group = group.split("\n")
    flag = 0
    for name in group:
        if "ENIQ_ADMIN_ROLE" in name:
            flag = 1
    if flag == 1:
        users = subprocess.check_output("lid -g ENIQ_ADMIN_ROLE",shell=True)
        users = users.split()
        for index, value in enumerate(users):
            users[index] = str(value).split('(')[0]
        return users
    else:
        logging.info('%s',err_group)
        return err_group

def ip_update_to_hostname():
    try:
        hostname = socket.gethostname()
        ip_define = "getent ahostsv4 " + hostname + " | awk '{print $1}' | head -1"
        get_ip = subprocess.check_output(ip_define, shell=True).strip()
        output_bytes = subprocess.check_output("cat /etc/ssh/sshd_config | grep AllowUsers", \
shell=True)
        output_str = output_bytes.decode('utf-8')
        modified_output_str = output_str
        for _ in get_ip:
            modified_output_str = modified_output_str.replace(get_ip, hostname)
        split = modified_output_str.split()
        unique_list = list(OrderedDict.fromkeys(split))
        delimiter = " "
        result_string = delimiter.join(unique_list)
        command = "sed -i '/^AllowUsers.*/c\\{0}' /etc/ssh/sshd_config".format(result_string)
        subprocess.check_output(command, shell=True)
        logging.info('Successfully updated IP addresses with Hostname\n')
        action = sys.argv[1] if len(sys.argv) > 1 else ""
        action = action.split()
        if "--skipug" in action:
            logging.info("Called by rollback script, Skipping execution of privileged \
user changes!")
        else:
            privileged_user_changes()
        config_file_path = '/etc/ssh/sshd_config'
        with open(config_file_path, 'r') as file:
            lines = file.readlines()
        seen_users = set()
        modified_lines = []
        for line in lines:
            if line.startswith('AllowUsers '):
                users = line.strip().split()[1:]
                unique_users = []
                for user in users:
                    if user not in seen_users:
                        seen_users.add(user)
                        unique_users.append(user)
                modified_line = 'AllowUsers ' + ' '.join(unique_users) + '\n'
                modified_lines.append(modified_line)
            else:
                modified_lines.append(line)
        with open(config_file_path, 'w') as file:
            file.writelines(modified_lines)
        os.system("sleep 3")
        os.system("systemctl restart sshd.service")
    except (subprocess.CalledProcessError, UnicodeDecodeError, AttributeError, OSError, \
ValueError) as e:
        print "Unable to update IP address"
        logging.warning("The following error has been observed : %s", e)

def privileged_user_changes():
    try:
        check_priv = subprocess.check_output("cat /etc/group", shell=True).strip().split(':')
        if "\nENIQ_ADMIN_ROLE" in check_priv:
            logging.info("Privileged user feature is activated\n")
            logging.info("Verifying the Interblade/Rack access!\n")
            os.system("sed -i 's/\\(\\S*\\)root@[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,\
3\\}\\.[0-9]\\{1,3\\}\\(.*\\)/\\1 \\2/g; s/  */ /g' /etc/ssh/sshd_config")
            os.system("sed -i 's/\\S*dcuser@[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,\
3\\}\\.[0-9]\\{1,3\\}//g' /etc/ssh/sshd_config")
            wc = subprocess.check_output("wc -l /eniq/sw/conf/server_types | awk '{print \
$1}'", shell=True).strip()
            if wc == "1":
                logging.info("The server is Single Blade/Rack, Internal SSH connections were \
already provided!\n")
            elif wc == "4":
                logging.info("The server is MultiBlade/Rack!\n")
                logging.info("Updating the inteblade SSH access for system users!\n")
                command = 'cat /eniq/sw/conf/server_types | awk -F "::" "{print \$(NF-1)}"'
                output = subprocess.check_output(command, shell=True).decode('utf-8')
                hostnames = output.strip().split('\n')
                new_users = []
                for ip in hostnames:
                    new_users.extend(['root@' + ip, 'dcuser@' + ip])
                new_users_string = ' '.join(new_users)
                sed_command = 'sed -i "/AllowUsers/ s/$/ {}/" /etc/ssh/sshd_config\
'.format(new_users_string)
                subprocess.call(sed_command, shell=True)
                logging.info("Successfully updated inteblade SSH access for system users!\n")
        else:
            logging.info("Privileged user feature is not activated!\n")
    except (subprocess.CalledProcessError, UnicodeDecodeError, AttributeError, OSError, \
ValueError) as e:
        print "Unable to update interblade SSH access for privileged user"
        print("The following error has been observed :", e)

if __name__ == '__main__':
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + 'enable_ssh_login.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,\
    filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,\
format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'enable_ssh_login.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        ssh_user(0)
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)