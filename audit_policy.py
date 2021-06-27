import strings


def auditpol_type(f, policy_setting, windows_value):
    if not windows_value == strings.CONFLICT:
        f.write(f"$b = {strings.AUDITPOL} | findstr /i /c:\"{policy_setting}\"\n")
        f.write("$a += if ($b -match \"" + windows_value + "\" ) {echo \"compliance\"} "
                                                           "else {echo \"Non compliance this value should be "
                + windows_value + "\"}\n")


def write_audit_policy_script(f, policy_type, policy_group, policy_setting,  windows_value):
    f.write("echo \"Policy Type Name : " + policy_type + "\" \n")
    f.write("echo \"Policy Group Name : " + policy_group + "\"\n")
    f.write("$a = \"" + policy_group + " : \" \n")
    auditpol_type(f, policy_setting, windows_value)
    f.write("write-output $a\n\n")
