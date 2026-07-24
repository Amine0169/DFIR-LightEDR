rule SuspiciousPowerShellEncoded {
    meta:
        description = "Detects encoded PowerShell commands indicative of obfuscation"
        author = "LightEDR"
        mitre_technique = "T1059.001"
        severity = "high"
    strings:
        $enc1 = "-enc" ascii nocase
        $enc2 = "-encodedcommand" ascii nocase
        $bypass = "bypass" ascii nocase
        $hidden = "-windowstyle hidden" ascii nocase
        $iex = "iex" ascii nocase
        $download = "downloadstring" ascii nocase
        $webclient = "webclient" ascii nocase
    condition:
        ($enc1 or $enc2) and ($bypass or $hidden or $iex or $download or $webclient)
}

rule MimikatzDetected {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        author = "LightEDR"
        mitre_technique = "T1003.001"
        severity = "critical"
    strings:
        $s1 = "mimikatz" ascii nocase
        $s2 = "privilege::debug" ascii nocase
        $s3 = "sekurlsa::logonpasswords" ascii nocase
        $s4 = "lsadump::" ascii nocase
        $s5 = "kerberos::" ascii nocase
    condition:
        any of ($s*)
}

rule SuspiciousMeterpreter {
    meta:
        description = "Detects Meterpreter payload indicators"
        author = "LightEDR"
        mitre_technique = "T1055"
        severity = "critical"
    strings:
        $s1 = "metsrv" ascii nocase
        $s2 = "meterpreter" ascii nocase
        $s3 = "reflective_loader" ascii nocase
        $s4 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 }
    condition:
        any of ($s*)
}
