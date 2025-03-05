rule ThreatFlux_Data_Leakage_Detection
{
    meta:
        description = "Detects potential data leakage related to ThreatFlux company and domain"
        author = "ThreatFlux"
        date = "2024-09-16"
        version = "1.0"
        file_type = "ANY"
        tlp = "AMBER"
        mitre_attack = "T1530"
        family = "DataLeakage.ThreatFlux"
        scope = "detection, hunting, intelligence-gathering"
        license = "MIT"
        references = "https://attack.mitre.org/techniques/T1530/"

    strings:
        $company_name1 = "ThreatFlux" nocase ascii wide
        $company_name2 = "Threat Flux" nocase ascii wide
        $domain = "threatflux.ai" nocase ascii wide        
        $email_pattern = /[a-zA-Z0-9._%+-]+@threatflux\.ai/ nocase ascii wide
        
        $confidential1 = "confidential" nocase ascii wide
        $confidential2 = "proprietary" nocase ascii wide
        $confidential3 = "internal use only" nocase ascii wide
        $confidential4 = "do not share" nocase ascii wide
        
        $file_extensions = /\.(docx?|xlsx?|pptx?|pdf|txt|csv)/ nocase ascii

    condition:
        (any of ($company_name*) or $domain or $email_pattern) and
        any of ($confidential*) and
        $file_extensions and
        filesize < 10MB
}

rule Detect_Credit_Card_Numbers
{
    meta:
        description = "Detects potential credit card numbers in various formats"
        author = "ThreatFlux"
        version = "1.0"
        date = "2024-09-16"
        file_type = "ANY"
        tlp = "WHITE"
        mitre_attack = "T1005"
        family = "PII.CreditCard"
        scope = "detection, hunting"
        license = "MIT"
        references = "https://www.pcisecuritystandards.org/documents/PCI_DSS_v3-2-1.pdf"
    strings: 
         $1 = "RegExp(\"[0-9]{13,16}\")"
    condition: 
         any of them
}

import "math"
include "../private/executables/native/pe.yar"
include "../private/archives/zip.yar"
include "../private/images/png.yar"
include "../private/images/jpg.yar"

rule Hunt_Encrypted_Data
{
    meta:
        description = "Detects potential presence of encrypted data in files"
        author = "ThreatFlux"
        date = "2024-09-16"
        version = "1.2"
        file_type = "ANY"
        tlp = "WHITE"
        mitre_attack = "T1027"
        family = "Generic.EncryptedData"
        scope = "hunting, intelligence-gathering"
        license = "MIT"
        references = "https://attack.mitre.org/techniques/T1027/"

    strings:
        $enc_header1 = "-----BEGIN ENCRYPTED" wide ascii
        $enc_header2 = "-----BEGIN PGP MESSAGE" wide ascii

        $enc_func1 = "Encrypt" fullword nocase wide ascii
        $enc_func2 = "AES" fullword nocase wide ascii
        $enc_func3 = "Rijndael" fullword nocase wide ascii
        $enc_func4 = "Blowfish" fullword nocase wide ascii
        $enc_func5 = "RC4" fullword nocase wide ascii
        $enc_func6 = "RSA" fullword nocase wide ascii

    condition:
        filesize > 512 and
        (
            // Check for known encrypted data headers
            any of ($enc_header*) or
            // Check for multiple encryption function names
            3 of ($enc_func*) or
            // Check for high entropy in file (possible encryption)
            math.entropy(0, filesize) >= 7.8
        ) and
        // Additional checks to reduce false positives
        not (
            // Exclude common file types
            uint32(0) == 0x464C457F or // ELF
            PE_Structure or // PE file
            uint32(0) == 0x66747970 or // MP4
            ZIP_Structure // ZIP
        )
}
