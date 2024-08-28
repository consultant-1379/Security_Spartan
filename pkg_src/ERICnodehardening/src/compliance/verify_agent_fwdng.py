#!/usr/bin/python
"""This script verifies if AgentForwarding has been disabled or not"""

def check_sshd_config():
    """This script verifies if AgentForwarding has been disabled or not"""
    if 'AllowAgentForwarding no' in open('/etc/ssh/sshd_config').read():
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'configure_sshd.py' TO MAKE IT COMPLIANT"

if __name__ == '__main__':
    check_sshd_config()
