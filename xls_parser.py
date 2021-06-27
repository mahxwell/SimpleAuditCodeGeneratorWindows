import pandas as pd
import strings
import audit_policy as auditp
import HKCU as hkcu
import HKLM as hklm
import security_template as s_template


def read_xlsx(path_to_file):
    data_xls = pd.read_excel(path_to_file, "Windows10Baseline", index_col=None)

    f = open("./audit.ps1", "a")

    # Read xlsx and write PowerShell script

    for i in range(len(data_xls)):

        # Write Audit Policy

        if data_xls[strings.POLICY_TYPE][i] == "Audit Policy":
            auditp.write_audit_policy_script(f, data_xls[strings.POLICY_TYPE][i],
                                             data_xls[strings.POLICY_GROUP_OR_REGISTRY_KEY][i],
                                             data_xls[strings.POLICY_SETTING][i],
                                             str(data_xls[strings.WINDOWS][i]))

        # Write HKCU

        if data_xls[strings.POLICY_TYPE][i] == "HKCU":
            hkcu.write_HKCU(f, data_xls[strings.POLICY_TYPE][i], data_xls[strings.POLICY_GROUP_OR_REGISTRY_KEY][i],
                            data_xls[strings.POLICY_SETTING][i],
                            str(data_xls[strings.WINDOWS][i]))

        # Write HKLM


        if data_xls[strings.POLICY_TYPE][i] == "HKLM":
            hklm.write_HKLM(f, data_xls[strings.POLICY_TYPE][i], data_xls[strings.POLICY_GROUP_OR_REGISTRY_KEY][i],
                            data_xls[strings.POLICY_SETTING][i],
                            str(data_xls[strings.WINDOWS][i]))


        # Write Security Template

        if data_xls[strings.POLICY_TYPE][i] == "Security Template":
            s_template.write_security_template(f, data_xls[strings.POLICY_TYPE][i],
                                               data_xls[strings.POLICY_GROUP_OR_REGISTRY_KEY][i],
                                               data_xls[strings.POLICY_SETTING][i],
                                               str(data_xls[strings.WINDOWS][i]))


    # Close File

    f.close()
