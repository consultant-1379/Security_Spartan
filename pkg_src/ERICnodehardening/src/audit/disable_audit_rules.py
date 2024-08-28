#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
# (c) Ericsson Radio Systems AB 2023 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : disable_audit_rules.py
# Purpose   : Script will provide the end-user to disable the audit rule
# Reason    : EQEV-102069
# Revision  : A
#
# ********************************************************************
"""
from __future__ import print_function
import sys
import os
import time
import logging
import shutil
sys.path.insert(0, '/ericsson/security/bin')
from user_verification import user_verification
from nh_verification import nh_check

TIME_EFFECT = ["-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change",
               "-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change"]

SYSTEM_LOCALE = ["-w /etc/hostname -p wa -k system-locale",
                 "-a always,exit -F dir=/etc/NetworkManager/ -F perm=wa -F key=system-locale"]

MEDIA_MOUNT_UNMOUNTING = ["-a always,exit -F arch=b64 -S mount -S umount2 -F dir=/media -k media"]
SYSTEM_STARTUP_SHUTDOWN = ["-w /sbin/shutdown -p x -k power",
                           "-w /sbin/poweroff -p x -k power",
                           "-w /sbin/reboot -p x -k power",
                           "-w /sbin/halt -p x -k power"]

PID_CHANGE = ["-w /bin/su -p xa -k priv_esc",
              "-w /usr/bin/sudo -p xa -k priv_esc",
              "-w /etc/sudoers -p rwa -k priv_esc"]

ATTEMPT_READ_INFO_AUDIT_RECORDS = ["-w /var/log/audit/ -p rw -k auditlog",
                                   "-w /var/log/audit/audit.log -p rw -k auditlog",
                                   "-w /etc/audit/audit.rules -p ra -k auditrules",
                                   "-w /etc/audit/rules.d/audit.rules -p ra -k auditmain"]

RPM = ["-w /usr/bin/rpm -p x -k software_mgmt", "-w /usr/bin/yum -p x -k software_mgmti"]

RULE_KILL = ["-a always,exit -F arch=b64 -S kill -F key=kill_rule"]

SYSTEM_BOOT_INFO_ACTIVITIES = ["-w /boot/grub2/grub.cfg -p w -k grub2_cfg",
                               "-w /etc/fstab -p w -k fstab",
                               "-w /etc/sysctl.conf -p w -k sysctl_conf",
                               "-w /etc/ssh/ssh_config -p warx -k ssh_config",
                               "-w /etc/ssh/sshd_config -p warx -k ssh_config",
                               "-w /etc/yum.repos.d/ -p w -k repos",
                               "-w /etc/profile -p w -k profile",
                               "-w /etc/multipath.conf -p w -k multipath",
                               "-w /etc/security/limits.conf -p w -k limits",
                               "-w /etc/securetty -p w -k securetty",
                               "-w /etc/hosts.allow -p w -k host_allow",
                               "-w /etc/hosts.deny -p w -k host_deny",
                               "-w /etc/sysconfig/network-scripts/ -p rwax -k fs_activity"]

OS_APP_CHANGE = ["-w /usr/bin/yum -p x -k yellowdog_update_mdfy",
                 "-w /usr/bin/rpm -p x -k redhat_package_Mgmt",
                 "-w /etc/redhat-release -p wx -k redhat_release",
                 "-w /usr/sbin/service  -p x -k service",
                 "-w /usr/bin/systemctl  -p x -k systemctl",
                 "-w /usr/sbin/mkfs.xfs  -p x -k mkfs_xfs",
                 "-w /usr/sbin/mkfs.ext4  -p x -k mkfs_ext4",
                 "-w /usr/sbin/mkswap  -p x -k mkswap",
                 "-w /usr/sbin/mkfs  -p x -k mkfs",
                 "-w /etc/lvm -p rwax -k lvm"]

SYSTEM_SCAN_OPEN_PORTS_SERVICES = ["-w /usr/bin/netstat -p x -k netstat",
                                   "-w /usr/sbin/route -p x -k route",
                                   "-w /usr/bin/firewall-cmd -p x -k firewall-cmd",
                                   "-w /etc/services -p rax -k services",
                                   "-w /usr/sbin/lsof -p x -k lsof",
                                   "-w /usr/sbin/nmap -p x -k nmap",
                                   "-w /sys/class/scsi_host/ -p rawx -k scsi_host",
                                   "-w /usr/bin/rescan-scsi-bus.sh -p rawx -k rescam_scsi_bus",
                                   "-w /usr/sbin/ss -p x -k ss",
                                   "-w /usr/sbin/iptables -p x -k iptables",
                                   "-w /usr/sbin/iptables-save -p x -k iptables-save",
                                   "-w /usr/bin/telnet -p x -k telnet",
                                   "-w /usr/bin/ftp -p x -k ftp"]

KEY_GENERATION_MANAGEMENT = ["-w /eniq/sw/runtime/java/bin/keytool -p x -k keytool",
                             "-w /usr/bin/ssh-keygen -p x -k keygen",
                             "-w /usr/bin/openssl -p x -k openssl"]

EXTERNAL_ACCESS = ["-a always,exit -F arch=b64 -S accept,connect -F key=external-access"]

def disable_audit_message():
    '''
    This function will provide the option and customer can select the features for disabling
    '''
    try:
        print("\033[93mWarning: Logs will not be captured for disabled rules. Proceed at your own risk!!!\
your own risk\033[00m\n")
        print("****** Select option for disabling audit rule ********\n")
        print("1: Time Effect")
        print("2: System Locale")
        print("3: Mac Policy")
        print("4: Discretionary Access Control Permission")
        print("5: Unauthorized Files Access Attempt")
        print("6: Mount rules")
        print("7: Privileged rules")
        print("8: Files Program Deletion")
        print("9: Modules rules")
        print("10: Scope rules")
        print("11: Identity rules")
        print("12: Sudo Cannot Record Action")
        print("13: Session")
        print("14: Login logout")
        if nh_check() == 1:
            print("15: PID Change")
            print("16: Audit record information attempts")
            print("17: Software Management")
            print("18: Rule Kill")
            print("19: System Config & File System Activities")
            print("20: OS Application Change")
            print("21: System Scan for Open Ports and Services")
            print("22: Keygenaration and Management")
            print("23: External Access")
            print("24: Media Mounting and Unmounting")
            print("25: System Startup and Shutdown")
    except (NameError, ValueError):
        print("Error in disabling audit rules")
        logging.info("Error in disabling audit rules")

def ciscat_disable_rules(file_read, update_rules_list):
    '''this fuction will Enforce the set of rules to disable
    '''
    file_read.seek(0)
    file_read.truncate(0)
    for data in range(len(update_rules_list)):
        file_read.writelines(update_rules_list[data])
    file_read.close()

def ciscat_read_file_content(file_read, rule_name):
    ''' this function will read the ciscat rules and disable it
    '''
    try:
        lines = file_read.readlines()
        status = []
        disable_status = "disable"
        update_rules_list = []
        disable_count = 0
        flag = 0
        for index, _ in enumerate(lines):
            check = lines[index][0]
            if check == '-':
                limit = "#"
                update_disable_rule = limit+lines[index]
                update_rules_list.append(update_disable_rule)
                disable_count = disable_count+1
                status.append(disable_status)
            if check == '#':
                dis_str = ' Already disabled'
                flag = flag+1
                logging.info("%s rule is already disabled", rule_name)
                status.append(dis_str)
        if flag > 1:
            print("{} rule is already disabled".format(rule_name))
        if len(update_rules_list) > 0:
            ciscat_disable_rules(file_read, update_rules_list)
        update_status = list(set(status))
        if len(update_status) == 1:
            logging.info("Info: "+ rule_name + " rule " + update_status[0])
        else:
            logging.info("Info: "+ rule_name + " rule " + update_status[0] + " " + update_status[1])
    except IndexError:
        print("selected rules file in /etc/audit/rules.d is empty!!!")
        logging.info("selected rules %s file in /etc/audit/rules.d is empty!!!",rule_name)

def read_file_content(file_read, disable_audit_list, rule_name):
    '''this function will disable the rules of config.txt and disable them'''
    lines = file_read.readlines()
    with open("/ericsson/security/audit/config.txt", 'w') as config_file:
        for _, rule in enumerate(disable_audit_list):
            for index, line in enumerate(lines):
                limit = "#"
                if rule == line.strip():
                    update_s1 = limit+rule
                    rule.replace(rule, update_s1)
                    new_line = line.replace(rule[0], '#'+rule[0], 1)
                    lines.pop(index)
                    lines.insert(index, new_line)
        config_file.writelines(lines)
        config_file.close()
    status = "Successfully disabled the config.txt " + rule_name + " rule"
    logging.info(status)

def get_disble_rule(selected_option):
    '''Based on user selection it will disable the rules
    '''
    try:
        file_read = open("/ericsson/security/audit/config.txt", "r+")
        if selected_option == 1:
            rule_name = "Time change"
            if nh_check() == 1:
                read_file_content(file_read, TIME_EFFECT, rule_name)
                ciscat_file_read = open("/etc/audit/rules.d/50-time_change.rules", "r+")
                ciscat_read_file_content(ciscat_file_read, rule_name)
            else:
                ciscat_file_read = open("/etc/audit/rules.d/50-time_change.rules", "r+")
                ciscat_read_file_content(ciscat_file_read, rule_name)
        if selected_option == 2:
            rule_name = "System locale"
            if nh_check() == 1:
                read_file_content(file_read, SYSTEM_LOCALE, rule_name)
                ciscat_file_read = open("/etc/audit/rules.d/50-system_local.rules", "r+")
                ciscat_read_file_content(ciscat_file_read, rule_name)
            else:
                ciscat_file_read = open("/etc/audit/rules.d/50-system_local.rules", "r+")
                ciscat_read_file_content(ciscat_file_read, rule_name)
        if selected_option == 3:
            rule_name = "MAC Policy"
            ciscat_file_read = open("/etc/audit/rules.d/50-MAC_policy.rules", "r+")
            ciscat_read_file_content(ciscat_file_read, rule_name)
        if selected_option == 4:
            rule_name = "Permission"
            ciscat_file_read = open("/etc/audit/rules.d/50-perm_mod.rules", "r+")
            ciscat_read_file_content(ciscat_file_read, rule_name)
        if selected_option == 5:
            rule_name = "Access"
            ciscat_file_read = open("/etc/audit/rules.d/50-access.rules", "r+")
            ciscat_read_file_content(ciscat_file_read, rule_name)
        if selected_option == 6:
            rule_name = "Mount"
            ciscat_file_read = open("/etc/audit/rules.d/50-mounts.rules", "r+")
            ciscat_read_file_content(ciscat_file_read, rule_name)
        if selected_option == 7:
            rule_name = "Privileged"
            ciscat_file_read = open("/etc/audit/rules.d/50-privileged.rules", "r+")
            ciscat_read_file_content(ciscat_file_read, rule_name)
        if selected_option == 8:
            rule_name = "Deletion"
            ciscat_file_read = open("/etc/audit/rules.d/50-deletion.rules", "r+")
            ciscat_read_file_content(ciscat_file_read, rule_name)
        if selected_option == 9:
            rule_name = "Module"
            ciscat_file_read = open("/etc/audit/rules.d/50-modules.rules", "r+")
            ciscat_read_file_content(ciscat_file_read, rule_name)
        if selected_option == 10:
            rule_name = "Scope"
            ciscat_file_read = open("/etc/audit/rules.d/50-scope.rules", "r+")
            ciscat_read_file_content(ciscat_file_read, rule_name)
        if selected_option == 11:
            rule_name = "Identity"
            ciscat_file_read = open("/etc/audit/rules.d/50-identity.rules", "r+")
            ciscat_read_file_content(ciscat_file_read, rule_name)
        if selected_option == 12:
            rule_name = "Action"
            ciscat_file_read = open("/etc/audit/rules.d/50-actions.rules", "r+")
            ciscat_read_file_content(ciscat_file_read, rule_name)
        if selected_option == 13:
            rule_name = "Session"
            ciscat_file_read = open("/etc/audit/rules.d/50-session.rules", "r+")
            ciscat_read_file_content(ciscat_file_read, rule_name)
        if selected_option == 14:
            rule_name = "Login-logout"
            ciscat_file_read = open("/etc/audit/rules.d/50-logins.rules", "r+")
            ciscat_read_file_content(ciscat_file_read, rule_name)
        if selected_option == 15:
            rule_name = "PID Change"
            read_file_content(file_read, PID_CHANGE, rule_name)
        if selected_option == 16:
            rule_name = "successful unsuccessful attempt read info audit records"
            read_file_content(file_read, ATTEMPT_READ_INFO_AUDIT_RECORDS, rule_name)
        if selected_option == 17:
            rule_name = "RPM"
            read_file_content(file_read, RPM, rule_name)
        if selected_option == 18:
            rule_name = "Rule kill"
            read_file_content(file_read, RULE_KILL, rule_name)
        if selected_option == 19:
            rule_name = "system boot info activities"
            read_file_content(file_read, SYSTEM_BOOT_INFO_ACTIVITIES, rule_name)
        if selected_option == 20:
            rule_name = "OS app change"
            read_file_content(file_read, OS_APP_CHANGE, rule_name)
            logging.info("successfully disable os app change")
        if selected_option == 21:
            rule_name = "System scan open port service"
            read_file_content(file_read, SYSTEM_SCAN_OPEN_PORTS_SERVICES, rule_name)
        if selected_option == 22:
            rule_name = "key generation management"
            read_file_content(file_read, KEY_GENERATION_MANAGEMENT, rule_name)
        if selected_option == 23:
            rule_name = "External access"
            read_file_content(file_read, EXTERNAL_ACCESS, rule_name)
        if selected_option == 24:
            rule_name = "Mount"
            read_file_content(file_read, MEDIA_MOUNT_UNMOUNTING, rule_name)
        if selected_option == 25:
            rule_name = "System startup shutdown"
            read_file_content(file_read, SYSTEM_STARTUP_SHUTDOWN, rule_name)
    except IOError:
        logging.info("One or more chosen features does not exit")
        print("One or more chosen features does not exit")

def disable_audit_main():
    '''
    Main function for disabling audit log
    '''
    disable_audit_message()
    main_list = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14',\
 '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25']
    user_selected = list(set([x for x in raw_input("\nPlease Select Your Options: ").split()]))
    check = all([item.isdigit() for item in user_selected])
    counter = 0
    res = False
    for i in user_selected:
        if i in main_list:
            counter += 1
    if counter == len(user_selected):
        res = True

    if check is True and res is True:
        for _, option in enumerate(user_selected):
            get_disble_rule(int(option))
        return True
    print("\033[93mPlease choose a valid options from the above given options\033[00m\n")
    logging.info("You have entered wrong option")
    return False

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FILENAME = TIMESTR + '_disable_audit_rules.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FILENAME,
                        format=FORMAT_STRING)
    RESULT = disable_audit_main()
    DISABLE_FLAG_STATUS = 0
    if RESULT is True:
        if nh_check() == 1:
            DISABLE_FLAG_STATUS = DISABLE_FLAG_STATUS+1
            if os.path.exists("/ericsson/security/audit/customize_flag_status.txt") is True:
                logging.info("The file is already present in the directory!!\n")
            else:
                os.system("touch /ericsson/security/audit/customize_flag_status.txt")
                logging.info("Successfully created the new file in the directory!!\n")
            with open("/ericsson/security/audit/customize_flag_status.txt", 'w') as customize_file:
                STATUS = "DISABLE_FLAG_STATUS "+str(DISABLE_FLAG_STATUS)
                customize_file.writelines(STATUS)
            customize_file.close()
            shutil.copyfile("/ericsson/security/audit/config.txt", "/ericsson/security/audit/customized_config.txt")
            os.system("python /ericsson/security/audit/audit_config.py")
            print("Rebooting the server.")
            logging.info("Rebooting the server.")
            os.system("reboot")
        else:
            print("Rebooting the server.")
            logging.info("Rebooting the server.")
            os.system("reboot")
    else:
        print("Rules are not Disabled EXECUTE 'disable_audit_rules.py'")
        logging.info("Rules are not Disabled EXECUTE 'disable_audit_rules.py'")