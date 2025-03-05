rule Hunt_Email_Addresses
{
    meta:
        description = "Hunts for potential email addresses in files"
        author = "ThreatFlux (improved by Claude)"
        date = "2024-09-17"
        version = "1.3"
        hash = "N/A"
        file_type = "ANY"
        tlp = "WHITE"
        family = "Generic.EmailHunting"
        mitre_attack = "T1114"
        scope = "hunting, intelligence-gathering"
        license = "MIT"
        references = "https://attack.mitre.org/techniques/T1114/"

    strings:
        $email_part1 = "mailto:" nocase ascii wide
        $email_part2 = "@gmail.com" nocase ascii wide
        $email_part3 = "@yahoo.com" nocase ascii wide
        $email_part4 = "@hotmail.com" nocase ascii wide
        $email_part5 = "@outlook.com" nocase ascii wide
        $email_part6 = "@example.com" nocase ascii wide

    condition:
        any of them and
        filesize < 64MB
}
