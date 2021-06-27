import strings


def security_template_type(f, policy_setting, windows_value, policy_group):
    if not windows_value == strings.CONFLICT:
        if policy_group == strings.PRIVILEGE_RIGHTS:
            f.write(f"$b = {strings.SECURITY_TEMPLATE_PRIV} | findstr /i /c:\"{policy_setting}\"\n")
            f.write("$a += if ($b -match \"" + windows_value + "\" ) {echo \"compliance\"} "
                                                               "else {echo \"Non compliance this value should be "
                    + windows_value + "\"}\n")
        if policy_group == strings.SERVICE_GEN_SETTING:
            return
        if policy_group == strings.SYSTEM_ACCESS:
            return


def write_security_template(f, policy_type, policy_group, policy_setting, windows_value):
    if strings.SRPV2 not in policy_group:
        f.write("echo \"Policy Type Name : " + policy_type + "\" \n")
        f.write("echo \"Policy Group Name : " + policy_group + "\"\n")
        f.write("$a = \"" + policy_group + " : \" \n")
        security_template_type(f, policy_setting, windows_value, policy_group)
        f.write("write-output $a\n\n")
