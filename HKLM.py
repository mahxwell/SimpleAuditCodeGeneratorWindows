import strings


def reg_query_type(f, policy_setting, windows_value, registry_key):
    if not windows_value == strings.CONFLICT:
        f.write(f"$b = {strings.REG_QUERY}" + f"\"{strings.HKEY_LOCAL_MACHINE}" +
                f"{registry_key}\" | findstr /i /c:\"{policy_setting}\"\n")
        f.write("$a += if ($b -match \"" + windows_value + "\" ) {echo \"compliance\"} "
                                                           "else {echo \"Non compliance this value should be "
                + windows_value + "\"}\n")


def write_HKLM(f, policy_type, registry_key, policy_setting, windows_value):
    if strings.SRPV2 not in registry_key:
        f.write("echo \"Policy Type Name : " + policy_type + "\" \n")
        f.write("echo \"Policy Group Name : " + registry_key + "\"\n")
        f.write("$a = \"" + registry_key + " : \" \n")
        reg_query_type(f, policy_setting, windows_value, registry_key)
        f.write("write-output $a\n\n")
