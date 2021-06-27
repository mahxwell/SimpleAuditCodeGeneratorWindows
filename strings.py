# Set Windows PowerShell Script ExecutionPolicy Rules

EXECUTION_POLICY_RESTRICTED = "Set-ExecutionPolicy -ExecutionPolicy restricted -force"
EXECUTION_POLICY_REMOTE_SIGNED = "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -force"

# Column names as constant and global variables

POLICY_TYPE = "Policy Type"
POLICY_GROUP_OR_REGISTRY_KEY = "Policy Group or Registry Key"
POLICY_SETTING = "Policy Setting"
WINDOWS = "Windows10H2"


#Windows Command

AUDITPOL = "auditpol /get /category:*"
REG_QUERY = "reg query "
HKEY_LOCAL_MACHINE = "HKLM\\"
HKEY_CURRENT_USER = "HKCU\\"
SECURITY_TEMPLATE_PRIV = "whoami /priv"

# REGEX

CONFLICT = "***CONFLICT***"
SRPV2 = "Software\\Policies\\Microsoft\\Windows\\SrpV2"
PRIVILEGE_RIGHTS = "Privilege Rights"
SERVICE_GEN_SETTING = "Service General Setting"
SYSTEM_ACCESS = "System Access"
