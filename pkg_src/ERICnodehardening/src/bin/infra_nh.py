#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Script for CIS/CAT automation """
# ****************************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ****************************************************************************
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
# ******************************************************************************
# Name      : infra_nh.py
# Purpose   : The script will perform CIS/CAT automation
# ******************************************************************************
"""
Modules used in the script
"""
import subprocess
import sys
import os
import logging
import time
import shutil
import datetime
from os.path import exists
from Verify_NH_Config import configure_nh

LOG_DIR = '/ericsson/security/log/Apply_NH_Logs/Manual_Exec/'
LOG_NAME = os.path.basename(__file__).replace('.py', '_')+time.strftime("%m_%d_%Y-%H_%M_%S")+'.log'

"""
Global variables used within the script
"""
GRUB_CONFIG_PATH = '/etc/default/grub'
EFI_PATH = '/sys/firmware/efi'
def check_userid():
    """
    This funtion is to check the user id,
    if user id not root then exit the script
    """
    if os.getuid() != 0:
        logging.error("Only root can execute the script")
        print("ERROR: Only Root can execute the script...")
        sys.exit(1)

def head():
    """
    Main Function
    """
    try:
        if not exists(LOG_DIR):
            os.makedirs(LOG_DIR)
        logging.basicConfig(level=logging.DEBUG, filename=LOG_DIR+LOG_NAME)
        print "Verifying the security settings"
        check_userid()
        configure_nh()
        devnull = open(os.devnull, 'w')
        file_path1 = "/etc/ssh/sshd_config"
        backup_path1 = "/etc/ssh/"
        file_name1 = os.path.basename(file_path1)
        file_path2 = "/etc/default/grub"
        file_name2 = os.path.basename(file_path2)
        backup_path2 = "/etc/default/"
        current_date = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        backup_file_name1 = file_name1.split(".")[0] + "_BKP_" + current_date
        shutil.copy(file_path1, backup_path1 + backup_file_name1)
        backup_file_name2 = file_name2.split(".")[0] + "_BKP_" + current_date
        shutil.copy(file_path2, backup_path2 + backup_file_name2)
        print"Ensuring mounting of cramfs filesystems is disabled"
        file = '/etc/modprobe.d/cramfs.conf'
        text = 'install cramfs /bin/true\n'
        cmd = 'rmmod cramfs'
        file_pointer = open(file, 'w')
        file_pointer.write(text)
        file_pointer.close()
        subprocess.call(cmd, shell=True, stderr=devnull)
        print"Ensured mounting of cramfs filesystems is disabled\n"
        logging.info("Ensured mounting of cramfs filesystems is disabled\n")
        print"Ensuring mounting of squashfs filesystems is disabled"
        file = '/etc/modprobe.d/squashfs.conf'
        text = 'install squashfs /bin/true\n'
        cmd = 'rmmod squashfs'
        file_pointer = open(file, 'w')
        file_pointer.write(text)
        file_pointer.close()
        subprocess.call(cmd, shell=True, stderr=devnull)
        print"Ensured mounting of squashfs filesystems is disabled\n"
        logging.info("Ensured mounting of squashfs filesystems is disabled\n")
        print"Ensuring mounting of udf filesystems is disabled"
        file = '/etc/modprobe.d/udf.conf'
        text = 'install udf /bin/true\n'
        cmd = 'rmmod udf'
        file_pointer = open(file, 'w')
        file_pointer.write(text)
        file_pointer.close()
        subprocess.call(cmd, shell=True, stderr=devnull)
        print"Ensured mounting of udf filesystems is disabled\n"
        logging.info("Ensured mounting of udf filesystems is disabled\n")
        print"Disabling USB Storage"
        file = '/etc/modprobe.d/usb_storage.conf'
        text = 'install usb-storage /bin/true\n'
        cmd = 'rmmod usb-storage'
        file_pointer = open(file, 'w')
        file_pointer.write(text)
        file_pointer.close()
        subprocess.call(cmd, shell=True, stderr=devnull)
        print"Disabled USB Storage\n"
        logging.info("Disabled USB Storage\n")
        print"Ensuring DCCP is disabled"
        file = '/etc/modprobe.d/dccp.conf'
        text = 'install dccp /bin/true\n'
        file_pointer = open(file, 'w')
        file_pointer.write(text)
        file_pointer.close()
        print"Ensured DCCP is disabled\n"
        logging.info("Ensured DCCP is disabled\n")
        print"Ensuring SCTP is disabled"
        file = '/etc/modprobe.d/sctp.conf'
        text = 'install sctp /bin/true\n'
        file_pointer = open(file, 'w')
        file_pointer.write(text)
        file_pointer.close()
        print"Ensured SCTP is disabled\n"
        logging.info("Ensured SCTP is disabled\n")
        print"Ensuring auditing for processes that start prior to auditd is enabled"
        file = GRUB_CONFIG_PATH
        text = 'audit=1'
        text1 = 'GRUB_CMDLINE_LINUX="'
        flag = 0
        file_pointer = open(file, 'r')
        out = file_pointer.readlines()
        file_pointer.close()
        for count, i in enumerate(out):
            if text1 in i:
                if text in i:
                    flag = 1
                else:
                    lines = out[count].split('"')
                    line1 = lines[1].split(' ')
                    output = lines[0] + '"' + line1[0] + ' ' +line1[1] + ' ' + text
                    for j in range(2, len(line1)):
                        output += ' ' + line1[j]
                    out[count] = output + '"' + '\n'
        if flag == 0:
            file_pointer = open(file, 'w')
            for i in out:
                file_pointer.write(i)
            file_pointer.close()
        if os.path.exists(EFI_PATH):
            cmd = "grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg"
        else:
            cmd = "grub2-mkconfig –o /boot/grub2/grub.cfg"
        subprocess.call(cmd, shell=True, stdout=devnull, stderr=subprocess.STDOUT)
        print"Ensured auditing for processes that start prior to auditd is enabled\n"
        logging.info("Ensured auditing for processes that start prior to auditd is enabled\n")
        print"Ensuring audit_backlog_limit is sufficient"
        file = GRUB_CONFIG_PATH
        text = 'audit_backlog_limit=8192'
        text1 = 'GRUB_CMDLINE_LINUX="'
        flag = 0
        file_pointer = open(file, 'r')
        out = file_pointer.readlines()
        file_pointer.close()
        for count, i in enumerate(out):
            if text1 in i:
                if text in i:
                    flag = 1
                else:
                    lines = out[count].split('"')
                    line1 = lines[1].split(' ')
                    output = lines[0] + '"' + line1[0] + ' ' +line1[1] + ' ' + line1[2] + ' ' + text
                    for j in range(3, len(line1)):
                        output += ' ' + line1[j]
                    out[count] = output + '"' + '\n'
        if flag == 0:
            file_pointer = open(file, 'w')
            for i in out:
                file_pointer.write(i)
            file_pointer.close()
        if os.path.exists(EFI_PATH):
            cmd = "grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg"
        else:
            cmd = "grub2-mkconfig –o /boot/grub2/grub.cfg"
        subprocess.call(cmd, shell=True, stdout=devnull, stderr=subprocess.STDOUT)
        print"Ensured audit_backlog_limit is sufficient\n"
        logging.info("Ensured audit_backlog_limit is sufficient\n")
        print"Ensuring sudo commands use pty"
        file = '/etc/sudoers'
        text = 'Defaults use_pty\n'
        flag = 0
        if exists(file):
            file_pointer = open(file, 'r')
            out = file_pointer.readlines()
            file_pointer.close()
            for i in enumerate(out):
                if text in i:
                    flag = 1
                    break
        if flag == 0:
            file_pointer = open(file, 'a')
            file_pointer.write(text)
            file_pointer.close()
        print"Ensured sudo commands use pty\n"
        logging.info("Ensured sudo commands use pty\n")
        print"Ensuring sudo log file exists"
        file = '/etc/sudoers'
        text = 'Defaults logfile="/var/log/sudo.log"\n'
        flag = 0
        if exists(file):
            file_pointer = open(file, 'r')
            out = file_pointer.readlines()
            file_pointer.close()
            for i in enumerate(out):
                if text in i:
                    flag = 1
                    break
        if flag == 0:
            file_pointer = open(file, 'a')
            file_pointer.write(text)
            file_pointer.close()
        print"Ensured sudo log file exists\n"
        logging.info("Ensured sudo log file exists\n")
        print"Ensuring chrony is configured"
        file = '/etc/sysconfig/chronyd'
        text = 'OPTIONS="-u chrony"\n'
        flag = 0
        if exists(file):
            file_pointer = open(file, 'r')
            out = file_pointer.readlines()
            file_pointer.close()
            for i in enumerate(out):
                if text in i:
                    flag = 1
                    break
        if flag == 0:
            file_pointer = open(file, 'a')
            file_pointer.write(text)
            file_pointer.close()
        print"Ensured chrony is configured\n"
        logging.info("Ensured chrony is configured\n")
        print"Ensuring noexec option set on /dev/shm partition"
        file = '/etc/fstab'
        text = 'tmpfs\t/dev/shm\ttmpfs\tnoexec\t0\t0\n'
        cmd = 'mount -o remount,noexec,nodev,nosuid /dev/shm'
        flag = 0
        if exists(file):
            file_pointer = open(file, 'r')
            out = file_pointer.readlines()
            file_pointer.close()
            for i in enumerate(out):
                if text in i:
                    flag = 1
                    break
        if flag == 0:
            file_pointer = open(file, 'a')
            file_pointer.write(text)
            file_pointer.close()
        subprocess.call(cmd, shell=True, stdout=subprocess.PIPE)
        print"Ensured noexec option set on /dev/shm partition\n"
        logging.info("Ensured noexec option set on /dev/shm partition\n")
        print"Disabling the rhnsd Daemon"
        cmd = 'systemctl --now mask rhnsd'
        code = subprocess.call(cmd, shell=True, stdout=subprocess.PIPE)
        if not code:
            print"Disabled the rhsnd daemon\n"
            logging.info("Disabled the rhsnd daemon\n")
        else:
            print"There was some issue with the command, returned non-zero exit status\n"
            logging.error("There was some issue with the command, returned non-zero exit status\n")
            sys.exit(1)
        logging.info("Ensuring that rsync service is masked\n")
        print"Ensuring that rsync service is masked\n"
        cmd = 'systemctl status rsyncd'
        out = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell= True)
        result = out.communicate()[0]

        if "disabled" in result:
            logging.info("service is disabled\n")
            print"Service is disabled\n"
            cmd1 = 'systemctl --now mask rsyncd'
            code = subprocess.call(cmd1, shell=True,stdout=devnull, stderr=devnull)
            if code == 0:
                logging.info("Service is masked\n")
                print"Service is masked\n"
            else:
                logging.warning("Service is not masked\n")
                print"Service not masked\n"
        else:
            if "masked" in result:
                logging.info("Service is already masked\n")
                print"Service is already masked\n"
            else:
                print"Service is not disabled\n"
                logging.error("Service is not disabled\n")
        print"Updating default grub parameters file"
        op = subprocess.check_output(["cat", "/etc/default/grub"])
        o2 = op.decode("utf-8")
        er = "ipv6.disable=1"
        if er in o2:
            filename = GRUB_CONFIG_PATH
            er = ' ipv6.disable=1'
            with open(filename, "r") as f:
                content = f.read()
            content = content.replace(er, "")
            with open(filename, 'w') as f:
                f.write(content)
            f.close()
            print"ipv6 disable parameter removed from default grub parameter file\n"
            logging.info("Default grub parameter file updated\n")
        else:
            print"ipv6 disable parameter not exist in default Grub parameter file\n"
            logging.info("ipv6 disable parameter not exist in default Grub parameter file\n")
        msg="grub.cfg config file is being updated\n"
        if os.path.exists(EFI_PATH):
            print msg
            logging.info(msg)
            os.system('grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg 2>/dev/null')
        else:
            print msg
            logging.info(msg)
            os.system('grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null')
        print"Updating ssh sshd_config parameters file"
        op1 = subprocess.check_output(["cat", "/etc/ssh/sshd_config"])
        o3 = op1.decode("utf-8")
        er1 = "AddressFamily inet"
        if er1 in o3:
            filename1 = '/etc/ssh/sshd_config'
            er1 = 'AddressFamily inet'
            with open(filename1, "r") as f1:
                content1 = f1.read()
            content1 = content1.replace(er1, "")
            with open(filename1, 'w') as f1:
                f1.write(content1)
            f1.close()
            print"AddressFamily inet removed from ssh_sshd_config parameter file\n"
            logging.info("Ssh ssh_sshd_config parameter file updated\n")
            os.system('systemctl restart sshd')
        else:
            print"AddressFamily inet parameter not exist in ssh_sshd_config parameter file"
            logging.info("AddressFamily inet parameter not exist in ssh_sshd_config parameter file\n")
    except Exception, e:
        print"Script exited abnormally"
        print"Please check logs at - %s"%(LOG_DIR+LOG_NAME)
        logging.error(e)

if __name__ == "__main__":
    head()