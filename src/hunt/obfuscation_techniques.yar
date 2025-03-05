import "pe"
import "math"

rule Hunt_Obfuscation_Techniques
{
    meta:
        description = "Detects common obfuscation techniques used in malicious scripts and executables"
        author = "ThreatFlux,"
        date = "2024-09-16"
        version = "1.1"
        hash = "N/A"
        file_type = "EXE/SCRIPT"
        tlp = "WHITE"
        mitre_attack = "T1027"
        family = "Generic.Obfuscation"
        scope = "hunting, intelligence-gathering"
        license = "MIT"
        references = "https://attack.mitre.org/techniques/T1027/"

    strings:
        // String obfuscation techniques
        $hex_encoded = "\\x" ascii
        $unicode_encoded = "\\u00" ascii
        $decimal_encoded = "&#" ascii

        // Script obfuscation techniques
        $eval_usage = "eval(" nocase ascii
        $fromcharcode = "String.fromCharCode(" nocase ascii

        // PowerShell specific obfuscation
        $ps_encoded_cmd = "-enc" nocase ascii
        $ps_compressed = "[System.Convert]::FromBase64String(" nocase ascii

        // Executable obfuscation indicators
        $packed_section = ".packed" ascii
        $encrypted_section = ".encrypt" ascii

    condition:
        (
            // For script files
            (uint16(0) == 0x3F3C or // PHP
             uint32(0) == 0x204D3C3C or // ASP
             uint16(0) == 0x5A4D) // PE files
            and
            (
                (#hex_encoded > 10 and #unicode_encoded > 5) or
                #decimal_encoded > 10 or
                $eval_usage or
                $fromcharcode or
                ($ps_encoded_cmd and $ps_compressed)
            )
        )
        or
        (
            // For PE files
            uint16(0) == 0x5A4D and
            pe.number_of_sections > 3 and
            (
                $packed_section or
                $encrypted_section or
                math.entropy(0, filesize) >= 7.2
            )
        )
}
