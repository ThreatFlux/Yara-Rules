rule Hunt_Potential_Encryption_Keys
{
    meta:
        description = "Hunts for potential encryption keys in various formats"
        author = "ThreatFlux"
        version = "1.1"
        date = "2024-09-17"
        file_type = "ANY"
        tlp = "WHITE"
        mitre_attack = "T1552.004"
        family = "Generic.EncryptionKey"
        scope = "hunting, intelligence-gathering"
        license = "MIT"
        references = "https://attack.mitre.org/techniques/T1552/004/"

    strings:
        // RSA Private Key patterns
        $rsa_private1 = "-----BEGIN RSA PRIVATE KEY-----" ascii wide
        $rsa_private2 = "-----END RSA PRIVATE KEY-----" ascii wide

        // PGP Private Key patterns
        $pgp_private1 = "-----BEGIN PGP PRIVATE KEY BLOCK-----" ascii wide
        $pgp_private2 = "-----END PGP PRIVATE KEY BLOCK-----" ascii wide

        // SSH Private Key patterns
        $ssh_private1 = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii wide
        $ssh_private2 = "-----END OPENSSH PRIVATE KEY-----" ascii wide

        // Common key-related keywords
        $key_keywords1 = "encryption key" nocase ascii wide
        $key_keywords2 = "secret key" nocase ascii wide
        $key_keywords3 = "private key" nocase ascii wide
        $key_keywords4 = "shared key" nocase ascii wide

        // Base64 indicators (not a full pattern)
        $base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" ascii wide

        // Hex indicators (not a full pattern)
        $hex_chars = "0123456789ABCDEFabcdef" ascii wide

    condition:
        any of ($rsa_private*, $pgp_private*, $ssh_private*) or
        (
            filesize < 1MB and
            any of ($key_keywords*) and
            (
                (
                    $base64_chars and
                    #base64_chars > 32
                ) or
                (
                    $hex_chars and
                    #hex_chars > 32
                )
            )
        )
}
