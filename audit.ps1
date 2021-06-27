echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Account Logon"
$a = "Account Logon : " 
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Account Logon"
$a = "Account Logon : " 
$b = auditpol /get /category:* | findstr /i /c:"Kerberos Authentication Service"
$a += if ($b -match "Success and Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Account Logon"
$a = "Account Logon : " 
$b = auditpol /get /category:* | findstr /i /c:"Kerberos Service Ticket Operations"
$a += if ($b -match "Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Account Management"
$a = "Account Management : " 
$b = auditpol /get /category:* | findstr /i /c:"Computer Account Management"
$a += if ($b -match "Success" ) {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Account Management"
$a = "Account Management : " 
$b = auditpol /get /category:* | findstr /i /c:"Other Account Management Events"
$a += if ($b -match "Success" ) {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Account Management"
$a = "Account Management : " 
$b = auditpol /get /category:* | findstr /i /c:"Security Group Management"
$a += if ($b -match "Success" ) {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Account Management"
$a = "Account Management : " 
$b = auditpol /get /category:* | findstr /i /c:"User Account Management"
$a += if ($b -match "Success and Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Detailed Tracking"
$a = "Detailed Tracking : " 
$b = auditpol /get /category:* | findstr /i /c:"Plug and Play Events"
$a += if ($b -match "Success" ) {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Detailed Tracking"
$a = "Detailed Tracking : " 
$b = auditpol /get /category:* | findstr /i /c:"Process Creation"
$a += if ($b -match "Success" ) {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : DS Access"
$a = "DS Access : " 
$b = auditpol /get /category:* | findstr /i /c:"Directory Service Access"
$a += if ($b -match "Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : DS Access"
$a = "DS Access : " 
$b = auditpol /get /category:* | findstr /i /c:"Directory Service Changes"
$a += if ($b -match "Success" ) {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Logon/Logoff"
$a = "Logon/Logoff : " 
$b = auditpol /get /category:* | findstr /i /c:"Account Lockout"
$a += if ($b -match "Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Logon/Logoff"
$a = "Logon/Logoff : " 
$b = auditpol /get /category:* | findstr /i /c:"Group Membership"
$a += if ($b -match "Success" ) {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Logon/Logoff"
$a = "Logon/Logoff : " 
$b = auditpol /get /category:* | findstr /i /c:"Logon"
$a += if ($b -match "Success and Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Logon/Logoff"
$a = "Logon/Logoff : " 
$b = auditpol /get /category:* | findstr /i /c:"Other Logon/Logoff Events"
$a += if ($b -match "Success and Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Logon/Logoff"
$a = "Logon/Logoff : " 
$b = auditpol /get /category:* | findstr /i /c:"Special Logon"
$a += if ($b -match "Success" ) {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Object Access"
$a = "Object Access : " 
$b = auditpol /get /category:* | findstr /i /c:"Detailed File Share"
$a += if ($b -match "Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Object Access"
$a = "Object Access : " 
$b = auditpol /get /category:* | findstr /i /c:"File Share"
$a += if ($b -match "Success and Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Object Access"
$a = "Object Access : " 
$b = auditpol /get /category:* | findstr /i /c:"Other Object Access Events"
$a += if ($b -match "Success and Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Object Access"
$a = "Object Access : " 
$b = auditpol /get /category:* | findstr /i /c:"Removable Storage"
$a += if ($b -match "Success and Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Policy Change"
$a = "Policy Change : " 
$b = auditpol /get /category:* | findstr /i /c:"Audit Policy Change"
$a += if ($b -match "Success" ) {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Policy Change"
$a = "Policy Change : " 
$b = auditpol /get /category:* | findstr /i /c:"Authentication Policy Change"
$a += if ($b -match "Success" ) {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Policy Change"
$a = "Policy Change : " 
$b = auditpol /get /category:* | findstr /i /c:"MPSSVC Rule-Level Policy Change"
$a += if ($b -match "Success and Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Policy Change"
$a = "Policy Change : " 
$b = auditpol /get /category:* | findstr /i /c:"Other Policy Change Events"
$a += if ($b -match "Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : Privilege Use"
$a = "Privilege Use : " 
$b = auditpol /get /category:* | findstr /i /c:"Sensitive Privilege Use"
$a += if ($b -match "Success and Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : System"
$a = "System : " 
$b = auditpol /get /category:* | findstr /i /c:"Other System Events"
$a += if ($b -match "Success and Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : System"
$a = "System : " 
$b = auditpol /get /category:* | findstr /i /c:"Security State Change"
$a += if ($b -match "Success" ) {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : System"
$a = "System : " 
$b = auditpol /get /category:* | findstr /i /c:"Security System Extension"
$a += if ($b -match "Success" ) {echo "compliance"} else {echo "Non compliance this value should be Success"}
write-output $a

echo "Policy Type Name : Audit Policy" 
echo "Policy Group Name : System"
$a = "System : " 
$b = auditpol /get /category:* | findstr /i /c:"System Integrity"
$a += if ($b -match "Success and Failure" ) {echo "compliance"} else {echo "Non compliance this value should be Success and Failure"}
write-output $a

echo "Policy Type Name : HKCU" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Control Panel"
$a = "Software\Policies\Microsoft\Internet Explorer\Control Panel : " 
$b = reg query "HKCU\Software\Policies\Microsoft\Internet Explorer\Control Panel" | findstr /i /c:"FormSuggest Passwords"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKCU" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main"
$a = "Software\Policies\Microsoft\Internet Explorer\Main : " 
$b = reg query "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" | findstr /i /c:"FormSuggest Passwords"
$a += if ($b -match "no" ) {echo "compliance"} else {echo "Non compliance this value should be no"}
write-output $a

echo "Policy Type Name : HKCU" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main"
$a = "Software\Policies\Microsoft\Internet Explorer\Main : " 
$b = reg query "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" | findstr /i /c:"FormSuggest PW Ask"
$a += if ($b -match "no" ) {echo "compliance"} else {echo "Non compliance this value should be no"}
write-output $a

echo "Policy Type Name : HKCU" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CloudContent"
$a = "Software\Policies\Microsoft\Windows\CloudContent : " 
$b = reg query "HKCU\Software\Policies\Microsoft\Windows\CloudContent" | findstr /i /c:"DisableThirdPartySuggestions"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKCU" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications : " 
$b = reg query "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" | findstr /i /c:"NoToastApplicationNotificationOnLockScreen"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\WcmSvc\wifinetworkmanager\config"
$a = "Software\Microsoft\WcmSvc\wifinetworkmanager\config : " 
$b = reg query "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\config" | findstr /i /c:"AutoConnectAllowedOEM"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$a = "Software\Microsoft\Windows NT\CurrentVersion\Winlogon : " 
$b = reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i /c:"ScRemoveOption"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\CredUI"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\CredUI : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" | findstr /i /c:"EnumerateAdministrators"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | findstr /i /c:"NoAutorun"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | findstr /i /c:"NoDriveTypeAutoRun"
$a += if ($b -match "255" ) {echo "compliance"} else {echo "Non compliance this value should be 255"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | findstr /i /c:"NoWebServices"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\Ext"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\Ext : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" | findstr /i /c:"RunThisTimeEnabled"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\Ext"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\Ext : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" | findstr /i /c:"VersionCheckEnabled"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\System"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\System : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i /c:"ConsentPromptBehaviorAdmin"
$a += if ($b -match "2" ) {echo "compliance"} else {echo "Non compliance this value should be 2"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\System"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\System : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i /c:"ConsentPromptBehaviorUser"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\System"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\System : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i /c:"DisableAutomaticRestartSignOn"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\System"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\System : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i /c:"EnableInstallerDetection"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\System"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\System : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i /c:"EnableLUA"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\System"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\System : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i /c:"EnableSecureUIAPaths"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\System"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\System : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i /c:"EnableVirtualization"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\System"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\System : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i /c:"FilterAdministratorToken"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\System"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\System : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i /c:"InactivityTimeoutSecs"
$a += if ($b -match "900" ) {echo "compliance"} else {echo "Non compliance this value should be 900"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\System"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\System : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i /c:"LocalAccountTokenFilterPolicy"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\System"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\System : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i /c:"MSAOptional"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
$a = "Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters : " 
$b = reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" | findstr /i /c:"AllowEncryptionOracle"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft Services\AdmPwd"
$a = "Software\Policies\Microsoft Services\AdmPwd : " 
$b = reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" | findstr /i /c:"AdmPwdEnabled"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Biometrics\FacialFeatures"
$a = "Software\Policies\Microsoft\Biometrics\FacialFeatures : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Biometrics\FacialFeatures" | findstr /i /c:"EnhancedAntiSpoofing"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\FVE"
$a = "SOFTWARE\Policies\Microsoft\FVE : " 
$b = reg query "HKLM\SOFTWARE\Policies\Microsoft\FVE" | findstr /i /c:"DisableExternalDMAUnderLock"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\FVE"
$a = "SOFTWARE\Policies\Microsoft\FVE : " 
$b = reg query "HKLM\SOFTWARE\Policies\Microsoft\FVE" | findstr /i /c:"RDVDenyCrossOrg"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\FVE"
$a = "SOFTWARE\Policies\Microsoft\FVE : " 
$b = reg query "HKLM\SOFTWARE\Policies\Microsoft\FVE" | findstr /i /c:"UseEnhancedPin"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Download"
$a = "Software\Policies\Microsoft\Internet Explorer\Download : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Download" | findstr /i /c:"CheckExeSignatures"
$a += if ($b -match "yes" ) {echo "compliance"} else {echo "Non compliance this value should be yes"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Download"
$a = "Software\Policies\Microsoft\Internet Explorer\Download : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Download" | findstr /i /c:"RunInvalidSignatures"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Feeds"
$a = "Software\Policies\Microsoft\Internet Explorer\Feeds : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds" | findstr /i /c:"DisableEnclosureDownload"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main"
$a = "Software\Policies\Microsoft\Internet Explorer\Main : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" | findstr /i /c:"DisableEPMCompat"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main"
$a = "Software\Policies\Microsoft\Internet Explorer\Main : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" | findstr /i /c:"Isolation"
$a += if ($b -match "PMEM" ) {echo "compliance"} else {echo "Non compliance this value should be PMEM"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main"
$a = "Software\Policies\Microsoft\Internet Explorer\Main : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" | findstr /i /c:"Isolation64Bit"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" | findstr /i /c:"(Reserved)"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" | findstr /i /c:"explorer.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" | findstr /i /c:"iexplore.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" | findstr /i /c:"(Reserved)"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" | findstr /i /c:"explorer.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" | findstr /i /c:"iexplore.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" | findstr /i /c:"(Reserved)"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" | findstr /i /c:"explorer.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" | findstr /i /c:"iexplore.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" | findstr /i /c:"(Reserved)"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" | findstr /i /c:"explorer.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" | findstr /i /c:"iexplore.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" | findstr /i /c:"(Reserved)"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" | findstr /i /c:"explorer.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" | findstr /i /c:"iexplore.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" | findstr /i /c:"(Reserved)"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" | findstr /i /c:"explorer.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" | findstr /i /c:"iexplore.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" | findstr /i /c:"(Reserved)"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" | findstr /i /c:"explorer.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" | findstr /i /c:"iexplore.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" | findstr /i /c:"(Reserved)"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" | findstr /i /c:"explorer.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"
$a = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" | findstr /i /c:"iexplore.exe"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\PhishingFilter"
$a = "Software\Policies\Microsoft\Internet Explorer\PhishingFilter : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" | findstr /i /c:"EnabledV9"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\PhishingFilter"
$a = "Software\Policies\Microsoft\Internet Explorer\PhishingFilter : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" | findstr /i /c:"PreventOverride"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\PhishingFilter"
$a = "Software\Policies\Microsoft\Internet Explorer\PhishingFilter : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" | findstr /i /c:"PreventOverrideAppRepUnknown"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Restrictions"
$a = "Software\Policies\Microsoft\Internet Explorer\Restrictions : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Restrictions" | findstr /i /c:"NoCrashDetection"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Security"
$a = "Software\Policies\Microsoft\Internet Explorer\Security : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Security" | findstr /i /c:"DisableSecuritySettingsCheck"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Internet Explorer\Security\ActiveX"
$a = "Software\Policies\Microsoft\Internet Explorer\Security\ActiveX : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX" | findstr /i /c:"BlockNonAdminActiveXInstall"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\MicrosoftEdge\Internet Settings"
$a = "Software\Policies\Microsoft\MicrosoftEdge\Internet Settings : " 
$b = reg query "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Internet Settings" | findstr /i /c:"PreventCertErrorOverrides"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\MicrosoftEdge\Main"
$a = "Software\Policies\Microsoft\MicrosoftEdge\Main : " 
$b = reg query "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" | findstr /i /c:"FormSuggest Passwords"
$a += if ($b -match "no" ) {echo "compliance"} else {echo "Non compliance this value should be no"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
$a = "Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter : " 
$b = reg query "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" | findstr /i /c:"EnabledV9"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
$a = "Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter : " 
$b = reg query "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" | findstr /i /c:"PreventOverride"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
$a = "Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter : " 
$b = reg query "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" | findstr /i /c:"PreventOverrideAppRepUnknown"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$a = "Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" | findstr /i /c:"ACSettingIndex"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$a = "Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" | findstr /i /c:"DCSettingIndex"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab"
$a = "SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab : " 
$b = reg query "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" | findstr /i /c:"ACSettingIndex"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab"
$a = "SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab : " 
$b = reg query "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" | findstr /i /c:"DCSettingIndex"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender"
$a = "Software\Policies\Microsoft\Windows Defender : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender" | findstr /i /c:"PUAProtection"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\MpEngine"
$a = "Software\Policies\Microsoft\Windows Defender\MpEngine : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" | findstr /i /c:"MpCloudBlockLevel"
$a += if ($b -match "2" ) {echo "compliance"} else {echo "Non compliance this value should be 2"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
$a = "Software\Policies\Microsoft\Windows Defender\Real-Time Protection : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" | findstr /i /c:"DisableIOAVProtection"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
$a = "Software\Policies\Microsoft\Windows Defender\Real-Time Protection : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" | findstr /i /c:"DisableRealtimeMonitoring"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Scan"
$a = "Software\Policies\Microsoft\Windows Defender\Scan : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" | findstr /i /c:"DisableRemovableDriveScanning"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Spynet"
$a = "Software\Policies\Microsoft\Windows Defender\Spynet : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" | findstr /i /c:"DisableBlockAtFirstSeen"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Spynet"
$a = "Software\Policies\Microsoft\Windows Defender\Spynet : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" | findstr /i /c:"SpynetReporting"
$a += if ($b -match "2" ) {echo "compliance"} else {echo "Non compliance this value should be 2"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Spynet"
$a = "Software\Policies\Microsoft\Windows Defender\Spynet : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" | findstr /i /c:"SubmitSamplesConsent"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" | findstr /i /c:"ExploitGuard_ASR_Rules"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | findstr /i /c:"26190899-1602-49e8-8b27-eb1d0a1ce869"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | findstr /i /c:"3b576869-a4ec-4529-8536-b80a7769e899"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | findstr /i /c:"5beb7efe-fd9a-4556-801d-275e5ffc04cc"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | findstr /i /c:"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | findstr /i /c:"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | findstr /i /c:"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | findstr /i /c:"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | findstr /i /c:"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | findstr /i /c:"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | findstr /i /c:"c1db55ab-c21a-4637-bb3f-a12568109d35"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | findstr /i /c:"d3e037e1-3eb8-44c8-a917-57927947596d"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | findstr /i /c:"d4f940ab-401b-4efc-aadc-ad5f3c50688a"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | findstr /i /c:"e6db77e5-3df2-4cf1-b95a-636979351e5b"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
$a = "Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" | findstr /i /c:"EnableNetworkProtection"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows NT\DNSClient"
$a = "Software\Policies\Microsoft\Windows NT\DNSClient : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" | findstr /i /c:"EnableMulticast"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows NT\Printers"
$a = "Software\Policies\Microsoft\Windows NT\Printers : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers" | findstr /i /c:"DisableWebPnPDownload"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows NT\Rpc"
$a = "Software\Policies\Microsoft\Windows NT\Rpc : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows NT\Rpc" | findstr /i /c:"RestrictRemoteClients"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows NT\Terminal Services"
$a = "Software\Policies\Microsoft\Windows NT\Terminal Services : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" | findstr /i /c:"DisablePasswordSaving"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows NT\Terminal Services"
$a = "Software\Policies\Microsoft\Windows NT\Terminal Services : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" | findstr /i /c:"fAllowFullControl"
$a += if ($b -match "[[[delete]]]" ) {echo "compliance"} else {echo "Non compliance this value should be [[[delete]]]"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows NT\Terminal Services"
$a = "Software\Policies\Microsoft\Windows NT\Terminal Services : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" | findstr /i /c:"fAllowToGetHelp"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows NT\Terminal Services"
$a = "Software\Policies\Microsoft\Windows NT\Terminal Services : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" | findstr /i /c:"fDisableCdm"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows NT\Terminal Services"
$a = "Software\Policies\Microsoft\Windows NT\Terminal Services : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" | findstr /i /c:"fEncryptRPCTraffic"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows NT\Terminal Services"
$a = "Software\Policies\Microsoft\Windows NT\Terminal Services : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" | findstr /i /c:"fPromptForPassword"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows NT\Terminal Services"
$a = "Software\Policies\Microsoft\Windows NT\Terminal Services : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" | findstr /i /c:"fUseMailto"
$a += if ($b -match "[[[delete]]]" ) {echo "compliance"} else {echo "Non compliance this value should be [[[delete]]]"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows NT\Terminal Services"
$a = "Software\Policies\Microsoft\Windows NT\Terminal Services : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" | findstr /i /c:"MaxTicketExpiry"
$a += if ($b -match "[[[delete]]]" ) {echo "compliance"} else {echo "Non compliance this value should be [[[delete]]]"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows NT\Terminal Services"
$a = "Software\Policies\Microsoft\Windows NT\Terminal Services : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" | findstr /i /c:"MaxTicketExpiryUnits"
$a += if ($b -match "[[[delete]]]" ) {echo "compliance"} else {echo "Non compliance this value should be [[[delete]]]"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows NT\Terminal Services"
$a = "Software\Policies\Microsoft\Windows NT\Terminal Services : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" | findstr /i /c:"MinEncryptionLevel"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\AppPrivacy"
$a = "Software\Policies\Microsoft\Windows\AppPrivacy : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" | findstr /i /c:"LetAppsActivateWithVoiceAboveLock"
$a += if ($b -match "2" ) {echo "compliance"} else {echo "Non compliance this value should be 2"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\AxInstaller"
$a = "Software\Policies\Microsoft\Windows\AxInstaller : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\AxInstaller" | findstr /i /c:"OnlyUseAXISForActiveXInstall"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CloudContent"
$a = "Software\Policies\Microsoft\Windows\CloudContent : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CloudContent" | findstr /i /c:"DisableWindowsConsumerFeatures"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CredentialsDelegation"
$a = "Software\Policies\Microsoft\Windows\CredentialsDelegation : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CredentialsDelegation" | findstr /i /c:"AllowProtectedCreds"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" | findstr /i /c:"CertificateRevocation"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" | findstr /i /c:"EnableSSL3Fallback"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" | findstr /i /c:"PreventIgnoreCertErrors"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" | findstr /i /c:"SecureProtocols"
$a += if ($b -match "2560" ) {echo "compliance"} else {echo "Non compliance this value should be 2560"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" | findstr /i /c:"Security_HKLM_only"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" | findstr /i /c:"Security_options_edit"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" | findstr /i /c:"Security_zones_map_edit"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" | findstr /i /c:"WarnOnBadCertRecving"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" | findstr /i /c:"1C00"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" | findstr /i /c:"1C00"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" | findstr /i /c:"1C00"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" | findstr /i /c:"2301"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" | findstr /i /c:"1C00"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" | findstr /i /c:"2301"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" | findstr /i /c:"UNCAsIntranet"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" | findstr /i /c:"1C00"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" | findstr /i /c:"270C"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" | findstr /i /c:"1201"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" | findstr /i /c:"1C00"
$a += if ($b -match "65536" ) {echo "compliance"} else {echo "Non compliance this value should be 65536"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" | findstr /i /c:"270C"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" | findstr /i /c:"1201"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" | findstr /i /c:"1C00"
$a += if ($b -match "65536" ) {echo "compliance"} else {echo "Non compliance this value should be 65536"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" | findstr /i /c:"270C"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1001"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1004"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1201"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1206"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1209"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"120b"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"120c"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1406"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1407"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1409"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"140C"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1606"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1607"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"160A"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1802"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1804"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1806"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1809"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1A00"
$a += if ($b -match "65536" ) {echo "compliance"} else {echo "Non compliance this value should be 65536"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"1C00"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"2001"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"2004"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"2101"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"2102"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"2103"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"2200"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"2301"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"2402"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"2500"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"2708"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"2709"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" | findstr /i /c:"270C"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1001"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1004"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1200"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1201"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1206"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1209"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"120b"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"120c"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1400"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1402"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1405"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1406"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1407"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1409"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"140C"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1606"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1607"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1608"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"160A"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1802"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1803"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1804"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1806"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1809"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1A00"
$a += if ($b -match "196608" ) {echo "compliance"} else {echo "Non compliance this value should be 196608"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"1C00"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"2000"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"2001"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"2004"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"2101"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"2102"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"2103"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"2200"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"2301"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"2402"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"2500"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"2708"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"2709"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
$a = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" | findstr /i /c:"270C"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$a = "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard : " 
$b = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | findstr /i /c:"ConfigureSystemGuardLaunch"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$a = "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard : " 
$b = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | findstr /i /c:"EnableVirtualizationBasedSecurity"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$a = "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard : " 
$b = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | findstr /i /c:"HVCIMATRequired"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$a = "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard : " 
$b = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | findstr /i /c:"HypervisorEnforcedCodeIntegrity"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$a = "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard : " 
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$a = "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard : " 
$b = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | findstr /i /c:"RequirePlatformSecurityFeatures"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$a = "SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions : " 
$b = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" | findstr /i /c:"DenyDeviceClasses"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$a = "SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions : " 
$b = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" | findstr /i /c:"DenyDeviceClassesRetroactive"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
$a = "SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses : " 
$b = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" | findstr /i /c:"[[[Delete all values]]]"
$a += if ($b -match "nan" ) {echo "compliance"} else {echo "Non compliance this value should be nan"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
$a = "SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses : " 
$b = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" | findstr /i /c:"1"
$a += if ($b -match "{d48179be-ec20-11d1-b6b8-00c04fa372a7}" ) {echo "compliance"} else {echo "Non compliance this value should be {d48179be-ec20-11d1-b6b8-00c04fa372a7}"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\EventLog\Application"
$a = "Software\Policies\Microsoft\Windows\EventLog\Application : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\EventLog\Application" | findstr /i /c:"MaxSize"
$a += if ($b -match "32768" ) {echo "compliance"} else {echo "Non compliance this value should be 32768"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\EventLog\Security"
$a = "Software\Policies\Microsoft\Windows\EventLog\Security : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" | findstr /i /c:"MaxSize"
$a += if ($b -match "196608" ) {echo "compliance"} else {echo "Non compliance this value should be 196608"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\EventLog\System"
$a = "Software\Policies\Microsoft\Windows\EventLog\System : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\EventLog\System" | findstr /i /c:"MaxSize"
$a += if ($b -match "32768" ) {echo "compliance"} else {echo "Non compliance this value should be 32768"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\Explorer"
$a = "Software\Policies\Microsoft\Windows\Explorer : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\Explorer" | findstr /i /c:"NoAutoplayfornonVolume"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\GameDVR"
$a = "Software\Policies\Microsoft\Windows\GameDVR : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\GameDVR" | findstr /i /c:"AllowGameDVR"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$a = "Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2} : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" | findstr /i /c:"NoBackgroundPolicy"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$a = "Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2} : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" | findstr /i /c:"NoGPOListChanges"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\Installer"
$a = "Software\Policies\Microsoft\Windows\Installer : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\Installer" | findstr /i /c:"AlwaysInstallElevated"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\Installer"
$a = "Software\Policies\Microsoft\Windows\Installer : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\Installer" | findstr /i /c:"EnableUserControl"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\Kernel DMA Protection"
$a = "Software\Policies\Microsoft\Windows\Kernel DMA Protection : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\Kernel DMA Protection" | findstr /i /c:"DeviceEnumerationPolicy"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\LanmanWorkstation"
$a = "Software\Policies\Microsoft\Windows\LanmanWorkstation : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" | findstr /i /c:"AllowInsecureGuestAuth"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\Network Connections"
$a = "Software\Policies\Microsoft\Windows\Network Connections : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\Network Connections" | findstr /i /c:"NC_ShowSharedAccessUI"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
$a = "Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" | findstr /i /c:"\\*\NETLOGON"
$a += if ($b -match "RequireIntegrity=1,RequireMutualAuthentication=1" ) {echo "compliance"} else {echo "Non compliance this value should be RequireIntegrity=1,RequireMutualAuthentication=1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
$a = "Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" | findstr /i /c:"\\*\SYSVOL"
$a += if ($b -match "RequireIntegrity=1,RequireMutualAuthentication=1" ) {echo "compliance"} else {echo "Non compliance this value should be RequireIntegrity=1,RequireMutualAuthentication=1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\Personalization"
$a = "Software\Policies\Microsoft\Windows\Personalization : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\Personalization" | findstr /i /c:"NoLockScreenCamera"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\Personalization"
$a = "Software\Policies\Microsoft\Windows\Personalization : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\Personalization" | findstr /i /c:"NoLockScreenSlideshow"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$a = "Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" | findstr /i /c:"EnableScriptBlockInvocationLogging"
$a += if ($b -match "[[[delete]]]" ) {echo "compliance"} else {echo "Non compliance this value should be [[[delete]]]"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$a = "Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" | findstr /i /c:"EnableScriptBlockLogging"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\Safer"
$a = "Software\Policies\Microsoft\Windows\Safer : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\Safer" | findstr /i /c:"nan"
$a += if ($b -match "[[[create key]]]" ) {echo "compliance"} else {echo "Non compliance this value should be [[[create key]]]"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\System"
$a = "Software\Policies\Microsoft\Windows\System : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\System" | findstr /i /c:"AllowDomainPINLogon"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\System"
$a = "Software\Policies\Microsoft\Windows\System : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\System" | findstr /i /c:"EnableSmartScreen"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\System"
$a = "Software\Policies\Microsoft\Windows\System : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\System" | findstr /i /c:"EnumerateLocalUsers"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\System"
$a = "Software\Policies\Microsoft\Windows\System : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\System" | findstr /i /c:"ShellSmartScreenLevel"
$a += if ($b -match "Block" ) {echo "compliance"} else {echo "Non compliance this value should be Block"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
$a = "Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" | findstr /i /c:"fBlockNonDomain"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\Windows Search"
$a = "Software\Policies\Microsoft\Windows\Windows Search : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\Windows Search" | findstr /i /c:"AllowIndexingEncryptedStoresOrItems"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\WinRM\Client"
$a = "Software\Policies\Microsoft\Windows\WinRM\Client : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client" | findstr /i /c:"AllowBasic"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\WinRM\Client"
$a = "Software\Policies\Microsoft\Windows\WinRM\Client : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client" | findstr /i /c:"AllowDigest"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\WinRM\Client"
$a = "Software\Policies\Microsoft\Windows\WinRM\Client : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client" | findstr /i /c:"AllowUnencryptedTraffic"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\WinRM\Service"
$a = "Software\Policies\Microsoft\Windows\WinRM\Service : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" | findstr /i /c:"AllowBasic"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\WinRM\Service"
$a = "Software\Policies\Microsoft\Windows\WinRM\Service : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" | findstr /i /c:"AllowUnencryptedTraffic"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\Windows\WinRM\Service"
$a = "Software\Policies\Microsoft\Windows\WinRM\Service : " 
$b = reg query "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" | findstr /i /c:"DisableRunAs"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall"
$a = "Software\Policies\Microsoft\WindowsFirewall : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall" | findstr /i /c:"PolicyVersion"
$a += if ($b -match "538" ) {echo "compliance"} else {echo "Non compliance this value should be 538"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
$a = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" | findstr /i /c:"DefaultInboundAction"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
$a = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" | findstr /i /c:"DefaultOutboundAction"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
$a = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" | findstr /i /c:"DisableNotifications"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
$a = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" | findstr /i /c:"EnableFirewall"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
$a = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" | findstr /i /c:"LogDroppedPackets"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
$a = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" | findstr /i /c:"LogFileSize"
$a += if ($b -match "16384" ) {echo "compliance"} else {echo "Non compliance this value should be 16384"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
$a = "Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" | findstr /i /c:"LogSuccessfulConnections"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$a = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" | findstr /i /c:"DefaultInboundAction"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$a = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" | findstr /i /c:"DefaultOutboundAction"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$a = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" | findstr /i /c:"DisableNotifications"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$a = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" | findstr /i /c:"EnableFirewall"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
$a = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" | findstr /i /c:"LogDroppedPackets"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
$a = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" | findstr /i /c:"LogFileSize"
$a += if ($b -match "16384" ) {echo "compliance"} else {echo "Non compliance this value should be 16384"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
$a = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" | findstr /i /c:"LogSuccessfulConnections"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
$a = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" | findstr /i /c:"AllowLocalIPsecPolicyMerge"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
$a = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" | findstr /i /c:"AllowLocalPolicyMerge"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
$a = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" | findstr /i /c:"DefaultInboundAction"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
$a = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" | findstr /i /c:"DefaultOutboundAction"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
$a = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" | findstr /i /c:"DisableNotifications"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
$a = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" | findstr /i /c:"EnableFirewall"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
$a = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" | findstr /i /c:"LogDroppedPackets"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
$a = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" | findstr /i /c:"LogFileSize"
$a += if ($b -match "16384" ) {echo "compliance"} else {echo "Non compliance this value should be 16384"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
$a = "Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" | findstr /i /c:"LogSuccessfulConnections"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : Software\Policies\Microsoft\WindowsInkWorkspace"
$a = "Software\Policies\Microsoft\WindowsInkWorkspace : " 
$b = reg query "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" | findstr /i /c:"AllowWindowsInkWorkspace"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Control\Lsa"
$a = "System\CurrentControlSet\Control\Lsa : " 
$b = reg query "HKLM\System\CurrentControlSet\Control\Lsa" | findstr /i /c:"LimitBlankPasswordUse"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Control\Lsa"
$a = "System\CurrentControlSet\Control\Lsa : " 
$b = reg query "HKLM\System\CurrentControlSet\Control\Lsa" | findstr /i /c:"LmCompatibilityLevel"
$a += if ($b -match "5" ) {echo "compliance"} else {echo "Non compliance this value should be 5"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Control\Lsa"
$a = "System\CurrentControlSet\Control\Lsa : " 
$b = reg query "HKLM\System\CurrentControlSet\Control\Lsa" | findstr /i /c:"NoLMHash"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Control\Lsa"
$a = "System\CurrentControlSet\Control\Lsa : " 
$b = reg query "HKLM\System\CurrentControlSet\Control\Lsa" | findstr /i /c:"RestrictAnonymous"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Control\Lsa"
$a = "System\CurrentControlSet\Control\Lsa : " 
$b = reg query "HKLM\System\CurrentControlSet\Control\Lsa" | findstr /i /c:"RestrictAnonymousSAM"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Control\Lsa"
$a = "System\CurrentControlSet\Control\Lsa : " 
$b = reg query "HKLM\System\CurrentControlSet\Control\Lsa" | findstr /i /c:"RestrictRemoteSAM"
$a += if ($b -match "O:BAG:BAD:(A;;RC;;;BA)" ) {echo "compliance"} else {echo "Non compliance this value should be O:BAG:BAD:(A;;RC;;;BA)"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Control\Lsa"
$a = "System\CurrentControlSet\Control\Lsa : " 
$b = reg query "HKLM\System\CurrentControlSet\Control\Lsa" | findstr /i /c:"SCENoApplyLegacyAuditPolicy"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Control\Lsa\MSV1_0"
$a = "System\CurrentControlSet\Control\Lsa\MSV1_0 : " 
$b = reg query "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" | findstr /i /c:"allownullsessionfallback"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Control\Lsa\MSV1_0"
$a = "System\CurrentControlSet\Control\Lsa\MSV1_0 : " 
$b = reg query "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" | findstr /i /c:"NTLMMinClientSec"
$a += if ($b -match "537395200" ) {echo "compliance"} else {echo "Non compliance this value should be 537395200"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Control\Lsa\MSV1_0"
$a = "System\CurrentControlSet\Control\Lsa\MSV1_0 : " 
$b = reg query "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" | findstr /i /c:"NTLMMinServerSec"
$a += if ($b -match "537395200" ) {echo "compliance"} else {echo "Non compliance this value should be 537395200"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$a = "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest : " 
$b = reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" | findstr /i /c:"UseLogonCredential"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Control\Session Manager"
$a = "System\CurrentControlSet\Control\Session Manager : " 
$b = reg query "HKLM\System\CurrentControlSet\Control\Session Manager" | findstr /i /c:"ProtectionMode"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
$a = "SYSTEM\CurrentControlSet\Control\Session Manager\kernel : " 
$b = reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" | findstr /i /c:"DisableExceptionChainValidation"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
$a = "SYSTEM\CurrentControlSet\Policies\EarlyLaunch : " 
$b = reg query "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" | findstr /i /c:"DriverLoadPolicy"
$a += if ($b -match "3" ) {echo "compliance"} else {echo "Non compliance this value should be 3"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Policies\Microsoft\FVE"
$a = "System\CurrentControlSet\Policies\Microsoft\FVE : " 
$b = reg query "HKLM\System\CurrentControlSet\Policies\Microsoft\FVE" | findstr /i /c:"RDVDenyWriteAccess"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$a = "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters : " 
$b = reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" | findstr /i /c:"requiresecuritysignature"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$a = "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters : " 
$b = reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" | findstr /i /c:"RestrictNullSessAccess"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$a = "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters : " 
$b = reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" | findstr /i /c:"SMB1"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$a = "System\CurrentControlSet\Services\LanmanWorkstation\Parameters : " 
$b = reg query "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" | findstr /i /c:"EnablePlainTextPassword"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$a = "System\CurrentControlSet\Services\LanmanWorkstation\Parameters : " 
$b = reg query "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" | findstr /i /c:"RequireSecuritySignature"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Services\LDAP"
$a = "System\CurrentControlSet\Services\LDAP : " 
$b = reg query "HKLM\System\CurrentControlSet\Services\LDAP" | findstr /i /c:"LDAPClientIntegrity"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SYSTEM\CurrentControlSet\Services\MrxSmb10"
$a = "SYSTEM\CurrentControlSet\Services\MrxSmb10 : " 
$b = reg query "HKLM\SYSTEM\CurrentControlSet\Services\MrxSmb10" | findstr /i /c:"Start"
$a += if ($b -match "4" ) {echo "compliance"} else {echo "Non compliance this value should be 4"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SYSTEM\CurrentControlSet\Services\Netbt\Parameters"
$a = "SYSTEM\CurrentControlSet\Services\Netbt\Parameters : " 
$b = reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" | findstr /i /c:"NodeType"
$a += if ($b -match "2" ) {echo "compliance"} else {echo "Non compliance this value should be 2"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SYSTEM\CurrentControlSet\Services\Netbt\Parameters"
$a = "SYSTEM\CurrentControlSet\Services\Netbt\Parameters : " 
$b = reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" | findstr /i /c:"NoNameReleaseOnDemand"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Services\Netlogon\Parameters"
$a = "System\CurrentControlSet\Services\Netlogon\Parameters : " 
$b = reg query "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" | findstr /i /c:"requiresignorseal"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Services\Netlogon\Parameters"
$a = "System\CurrentControlSet\Services\Netlogon\Parameters : " 
$b = reg query "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" | findstr /i /c:"requirestrongkey"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Services\Netlogon\Parameters"
$a = "System\CurrentControlSet\Services\Netlogon\Parameters : " 
$b = reg query "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" | findstr /i /c:"sealsecurechannel"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Services\Netlogon\Parameters"
$a = "System\CurrentControlSet\Services\Netlogon\Parameters : " 
$b = reg query "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" | findstr /i /c:"signsecurechannel"
$a += if ($b -match "1" ) {echo "compliance"} else {echo "Non compliance this value should be 1"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Services\NTDS\Parameters"
$a = "System\CurrentControlSet\Services\NTDS\Parameters : " 
$b = reg query "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" | findstr /i /c:"LdapEnforceChannelBinding"
$a += if ($b -match "2" ) {echo "compliance"} else {echo "Non compliance this value should be 2"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : System\CurrentControlSet\Services\NTDS\Parameters"
$a = "System\CurrentControlSet\Services\NTDS\Parameters : " 
$b = reg query "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" | findstr /i /c:"LDAPServerIntegrity"
$a += if ($b -match "2" ) {echo "compliance"} else {echo "Non compliance this value should be 2"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$a = "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters : " 
$b = reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" | findstr /i /c:"DisableIPSourceRouting"
$a += if ($b -match "2" ) {echo "compliance"} else {echo "Non compliance this value should be 2"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$a = "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters : " 
$b = reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" | findstr /i /c:"EnableICMPRedirect"
$a += if ($b -match "0" ) {echo "compliance"} else {echo "Non compliance this value should be 0"}
write-output $a

echo "Policy Type Name : HKLM" 
echo "Policy Group Name : SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$a = "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters : " 
$b = reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" | findstr /i /c:"DisableIPSourceRouting"
$a += if ($b -match "2" ) {echo "compliance"} else {echo "Non compliance this value should be 2"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeBackupPrivilege"
$a += if ($b -match "*S-1-5-32-544" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-32-544"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeCreateGlobalPrivilege"
$a += if ($b -match "*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeCreatePagefilePrivilege"
$a += if ($b -match "*S-1-5-32-544" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-32-544"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeCreatePermanentPrivilege"
$a += if ($b -match "nan" ) {echo "compliance"} else {echo "Non compliance this value should be nan"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeCreateTokenPrivilege"
$a += if ($b -match "nan" ) {echo "compliance"} else {echo "Non compliance this value should be nan"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeDebugPrivilege"
$a += if ($b -match "*S-1-5-32-544" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-32-544"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeDenyRemoteInteractiveLogonRight"
$a += if ($b -match "*S-1-5-113" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-113"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeImpersonatePrivilege"
$a += if ($b -match "*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeLoadDriverPrivilege"
$a += if ($b -match "*S-1-5-32-544" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-32-544"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeLockMemoryPrivilege"
$a += if ($b -match "nan" ) {echo "compliance"} else {echo "Non compliance this value should be nan"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeManageVolumePrivilege"
$a += if ($b -match "*S-1-5-32-544" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-32-544"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeProfileSingleProcessPrivilege"
$a += if ($b -match "*S-1-5-32-544" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-32-544"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeRemoteInteractiveLogonRight"
$a += if ($b -match "*S-1-5-32-544" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-32-544"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeRemoteShutdownPrivilege"
$a += if ($b -match "*S-1-5-32-544" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-32-544"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeRestorePrivilege"
$a += if ($b -match "*S-1-5-32-544" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-32-544"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeSecurityPrivilege"
$a += if ($b -match "*S-1-5-32-544" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-32-544"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeSystemEnvironmentPrivilege"
$a += if ($b -match "*S-1-5-32-544" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-32-544"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeTakeOwnershipPrivilege"
$a += if ($b -match "*S-1-5-32-544" ) {echo "compliance"} else {echo "Non compliance this value should be *S-1-5-32-544"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeTcbPrivilege"
$a += if ($b -match "nan" ) {echo "compliance"} else {echo "Non compliance this value should be nan"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Privilege Rights"
$a = "Privilege Rights : " 
$b = whoami /priv | findstr /i /c:"SeTrustedCredManAccessPrivilege"
$a += if ($b -match "nan" ) {echo "compliance"} else {echo "Non compliance this value should be nan"}
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Service General Setting"
$a = "Service General Setting : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Service General Setting"
$a = "Service General Setting : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Service General Setting"
$a = "Service General Setting : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Service General Setting"
$a = "Service General Setting : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : Service General Setting"
$a = "Service General Setting : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : System Access"
$a = "System Access : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : System Access"
$a = "System Access : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : System Access"
$a = "System Access : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : System Access"
$a = "System Access : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : System Access"
$a = "System Access : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : System Access"
$a = "System Access : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : System Access"
$a = "System Access : " 
write-output $a

echo "Policy Type Name : Security Template" 
echo "Policy Group Name : System Access"
$a = "System Access : " 
write-output $a

