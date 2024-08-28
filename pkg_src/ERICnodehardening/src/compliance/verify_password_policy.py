#!/usr/bin/python
"""This script verifies the password policy enforced on the system or not"""
import os
import subprocess
import logging
import random
import string

def check_password_complexity():
    """This function is to verify the password complexity"""
    print "\nVerifying password complexity"
    print "\nCreating a test user to verify password complexity parameters"
    os.system("sleep 1s")
    os.system("useradd test > /dev/null 2>&1")

    print "\nVerifying password history is enforced"
    status_history = check_password_history()

    print "\nVerifying password complexity(uppercase, lowercase, special characters, numeric) \
is enforced"

    status_length = check_password_length()

    status_upper = check_uppercase()

    status_lower = check_lowercase()

    status_special = check_special_character()

    status_digit = check_digit()

#    print "\nVerifying dictionary checks are enforced"
#    status_dictionary=check_dictionary_word()

    #verify password hashing algorithm is set to sha512
    print "\nVerifying password hashing algorithm"
    status_hashing = check_password_hashing()
    print "\nRemoving the test user\n"
    os.system("sleep 1s")
    os.system("userdel -r test")
    os.system("rm -rf /home/test")
    os.system("rm -rf /ericsson/security/compliance/errorlog.txt")
    print"Verifying account lockout is configured or not"
    status_acc_lockout = check_lockout()

    if status_history and status_length and status_upper and status_lower and status_special \
and status_digit and status_hashing and status_acc_lockout:
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT: EXECUTE 'set_password_policy.py' TO MAKE IT COMPLIANT"

def passwd_generator(policy_type):
    """This is to generate a random password that will be used to test password policies"""
    rand_password = ""
    rand_lowercase_string = ''.join(random.choice(string.ascii_lowercase) for _ in range(4))
    rand_uppercase_string = ''.join(random.choice(string.ascii_uppercase) for _ in range(5))
    rand_digit = ''.join(random.choice(string.digits) for _ in range(5))

    if policy_type == "history":
        rand_password = rand_lowercase_string + rand_uppercase_string +'@'+ rand_digit
    if policy_type == "length":
        rand_password = rand_lowercase_string + rand_uppercase_string
    if policy_type == "upper_Case":
        rand_password = rand_lowercase_string + '@' + rand_digit
    if policy_type == "lower_Case":
        rand_password = rand_uppercase_string + '@' + rand_digit
    if policy_type == "special_character":
        rand_password = rand_lowercase_string + rand_uppercase_string + rand_digit
    if policy_type == "digits":
        rand_password = rand_lowercase_string + rand_uppercase_string + '@'

    rand_password = str(rand_password)
    return rand_password

def check_password_history():
    """This function is to check for the password history"""
    history = passwd_generator("history")

    compliance_pwd = "/ericsson/security/compliance/passwd.sh"
    with open(compliance_pwd, 'r') as fin:
        data = fin.readlines()

    index_value = 0
    line = " spawn passwd test\n"
    if line in data:
        index_value = data.index(line)
    insert_line = " " + "send " + "'" + history + r"\r'" + "\n"
    data.insert(index_value+2, insert_line)
    data.insert(index_value+4, insert_line)
    with open(compliance_pwd, 'w') as fout:
        fout.writelines(''.join(data))

    subprocess.call(['/ericsson/security/compliance/passwd.sh > /dev/null'], shell=True)
    value = False
    subprocess.call(['/ericsson/security/compliance/passwd.sh > \
/ericsson/security/compliance/pw.txt'], shell=True)
    if 'Password has been already used. Choose another.' in \
open('/ericsson/security/compliance/pw.txt').read():
        os.system("rm -rf /ericsson/security/compliance/pw.txt")
        logging.info("Password history is set")
        value = True
    else:
        os.system("rm -rf /ericsson/security/compliance/pw.txt")
        logging.error("Password history is not set")
        value = False

    data.pop(7)
    data.pop(8)
    with open(compliance_pwd, 'w') as fout:
        fout.writelines(''.join(data))

    return value

def check_password_length():
    """This function is to check for the password length"""
    rand_pwd = passwd_generator("length")
    os.system("echo '%s' | passwd test 2>&1 | tee /ericsson/security/compliance/errorlog.txt \
> /dev/null" % rand_pwd)

    if 'New password: BAD PASSWORD: The password contains less than 1 digits' in \
open('/ericsson/security/compliance/errorlog.txt').read():
        logging.info("Password length complexity has been set for 9 characters")
        return True
    else:
        logging.error("Password length complexity has not been set for 9 characters")
        return False

def check_uppercase():
    """This function is to check uppercase character"""
    rand_pwd = passwd_generator("upper_Case")
    os.system("echo '%s' | passwd test 2>&1 | tee /ericsson/security/compliance/errorlog.txt \
> /dev/null 2>&1" % rand_pwd)

    if 'New password: BAD PASSWORD: The password contains less than 1 uppercase letters' in \
open('/ericsson/security/compliance/errorlog.txt').read():
        logging.info("Password complexity ensures the pressence of atleast 1 uppercase character")
        return True
    else:
        logging.error("Password complexity does not ensures the pressence of atleast 1 \
uppercase character")
        return False

def check_lowercase():
    """This function is to check lowercase character"""
    rand_pwd = passwd_generator("lower_Case")
    os.system("echo '%s' | passwd test 2>&1 | tee /ericsson/security/compliance/errorlog.txt \
> /dev/null 2>&1" % rand_pwd)

    if 'New password: BAD PASSWORD: The password contains less than 1 lowercase letters' in \
open('/ericsson/security/compliance/errorlog.txt').read():
        logging.info("Password complexity ensures the pressence of atleast 1 lowercase character")
        return True
    else:
        logging.error("Password complexity does not ensures the pressence of atleast 1 \
lowercase character")
        return False

def check_special_character():
    """This function is to check special character"""
    rand_pwd = passwd_generator("special_character")
    os.system("echo '%s' | passwd test 2>&1 | tee /ericsson/security/compliance/errorlog.txt \
> /dev/null 2>&1" % rand_pwd)

    if 'New password: BAD PASSWORD: The password contains less than 1 non-alphanumeric characters'\
 in open('/ericsson/security/compliance/errorlog.txt').read():
        logging.info("Password complexity ensures the presence of atleast 1 non-alphanumeric \
character")
        return True
    else:
        logging.error("Password complexity does not ensures the presence of atleast 1 \
non-alphanumeric character")
        return False

def check_digit():
    """This function is to check the digit value"""
    rand_pwd = passwd_generator("digits")
    os.system("echo '%s' | passwd test 2>&1 | tee /ericsson/security/compliance/errorlog.txt \
> /dev/null 2>&1" % rand_pwd)

    if 'New password: BAD PASSWORD: The password contains less than 1 digits' in \
open('/ericsson/security/compliance/errorlog.txt').read():
        logging.info("Password complexity ensures the pressence of atleast 1 digit character")
        return True
    else:
        logging.error("Password complexity does not ensures the pressence of atleast 1 \
digit character")
        return False


#    """This function is to check the dictionary word"""
#    os.system("echo \"Welcome@123\" | passwd test 2>&1 | tee \
#/ericsson/security/compliance/errorlog.txt > /dev/null")

#    if 'New password: BAD PASSWORD: The password fails the dictionary check - it is based \
#on a dictionary word' in open('/ericsson/security/compliance/errorlog.txt').read():
#        logging.info("Password complexity enables dictionary check for passwords")
#        return True
#    else:
#        logging.error("Password complexity does not enables dictionary check for passwords")
#        return False

def check_password_hashing():
    """this function checks whether password hashing algorithm is sha512 or not."""
    status = subprocess.check_output("authconfig --test | grep hash | cut -d' ' -f 6", shell=True)
    if status == 'sha512\n':
        logging.info("strong password hashing algorithm is implemented")
        return True
    else:
        logging.error("password hashing algorihm being used is md5")
        return False

def check_lockout():
    """This function verifies if account lockout has been enforced or not."""
    data = open('/etc/pam.d/password-auth').read()
    if 'auth [success=1 default=ignore] pam_succeed_if.so user in root:dcuser' in data and \
'auth        required      pam_faillock.so preauth silent audit deny=5 unlock_time=1800' in data \
and 'auth        [default=die] pam_faillock.so authfail audit deny=5  unlock_time=1800' in data \
and 'account     required      pam_faillock.so' in data:
        return True
    else:
        return False

if __name__ == '__main__':
    check_password_complexity()
