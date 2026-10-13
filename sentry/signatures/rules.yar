// Optional YARA rules (used only if `pip install yara-python` succeeds).
rule Sentry_Ransom_Note_Text
{
    meta:
        description = "Generic ransom-note wording inside a file"
        severity = "high"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "all your files are encrypted" nocase
        $c = "to decrypt your files" nocase
        $d = "private key" nocase
        $e = "bitcoin" nocase
        $f = ".onion" nocase
        $g = "tor browser" nocase
    condition:
        2 of ($a, $b, $c) or (1 of ($a, $b, $c) and 2 of ($d, $e, $f, $g))
}

rule Sentry_Shadow_Copy_Deletion
{
    meta:
        description = "Executable contains shadow-copy / backup destruction commands"
        severity = "high"
    strings:
        $a = "vssadmin delete shadows" nocase ascii wide
        $b = "wmic shadowcopy delete" nocase ascii wide
        $c = "bcdedit /set {default} recoveryenabled no" nocase ascii wide
        $d = "wbadmin delete catalog" nocase ascii wide
        $e = "tmutil deletelocalsnapshots" nocase ascii wide
    condition:
        any of them
}

rule Sentry_Crypto_API_Plus_Enum
{
    meta:
        description = "PE imports file-encryption-capable crypto APIs and recursive file enumeration"
        severity = "medium"
    strings:
        $c1 = "CryptEncrypt" ascii
        $c2 = "CryptGenKey" ascii
        $c3 = "BCryptEncrypt" ascii
        $c4 = "CryptAcquireContext" ascii
        $f1 = "FindFirstFileW" ascii
        $f2 = "FindNextFileW" ascii
        $m  = "MoveFileExW" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($c*) and all of ($f*) and $m
}
