include "../../private/executables/native/pe.yar"

rule APT28_Zebrocy_Backdoor_PE {
    meta:
        description = "Detects Zebrocy backdoor used by APT28/Sofacy"
        author = "ThreatFlux"
        date = "2025-03-04"
        version = "1.0"
        reference = "https://www.welivesecurity.com/2018/11/20/sednit-whats-going-zebrocy/"
        file_type = "PE"
        malware_family = "Zebrocy"
        threat_actor = "APT28"
        confidence = "High"
        tlp = "AMBER"
    
    strings:
        // Example strings - these are placeholders and should be replaced with actual IOCs
        $s1 = "Zebrocy" nocase
        $s2 = "sofacy" nocase
        $s3 = "sednit" nocase
        
        // Optimized code patterns with fixed lengths
        $code1 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 08 48 85 C9 74 ?? FF 15 }
        $code2 = { 83 F8 64 73 ?? 48 8B 44 24 ?? 48 8B 4C 24 ?? 89 44 8E ?? 83 C0 01 }
        
    condition:
        PE_Structure and // PE file
        filesize < 2MB and
        (
            2 of ($s*) or
            any of ($code*) 
        )
}


rule APT28_Zebrocy_Config_Pattern {
    meta:
        description = "Detects Zebrocy configuration pattern"
        author = "ThreatFlux"
        date = "2025-03-04"
        version = "1.0"
        reference = "https://www.welivesecurity.com/2018/11/20/sednit-whats-going-zebrocy/"
        file_type = "PE"
        malware_family = "Zebrocy"
        threat_actor = "APT28"
        confidence = "High"
        tlp = "AMBER"
    
    strings:        
        // Known C2 addresses
        $c2_1 = "185.25.50.93" ascii wide
        $c2_2 = "185.25.51.198" ascii wide
        $c2_3 = "89.37.226.123" ascii wide
        
        // User agent string
        $ua = "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36" ascii wide
    
    condition:
        PE_Structure and // PE file
        filesize < 2MB and
        (
            any of ($c2_*) or
            $ua
        )
}
