import "pe"
rule procdump_tool {
    meta:
        description = "Simple YARA rule to detect the presence of Sysinternals Procdump"
        version = "1.0"
    strings:
        $s1 = "D:\\a\\1\\s\\x64\\Release\\ProcDump64.pdb" ascii
        $s2 = "Process cloning requires Windows 7 or higher." wide ascii
        $s3 = "ProcDump Timed" wide ascii
    condition:
        (uint16(0)) == 0x5A4D and (filesize < 500000) and (2 of ($s*))
        and pe.sections[4].name=="_RDATA"
}
