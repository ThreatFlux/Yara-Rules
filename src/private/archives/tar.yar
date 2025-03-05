private rule TAR_Structure
{
    meta:
        description = "Detects valid, extractable TAR archives"
        reference_files = "empty.tar (1276481102f218c981e0324180bafd9f)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "TAR"

    condition:
        // Header validation
        uint16(257) == 0x7573 and           // "us" in "ustar"
        uint32(257) == 0x74617273 and       // "tar" in "ustar"

        // Version check - must be either POSIX "00" or GNU " \0"
        (uint16(263) == 0x3030 or           // "00" - POSIX
         uint16(263) == 0x2000) and         // " \0" - GNU

        // Basic structure validation
        filesize >= 512 and                 // Minimum size (at least one block)
        filesize % 512 == 0 and             // Size must be multiple of 512 bytes

        // Checksum validation - first byte must be valid octal
        (uint8(148) >= 0x30 and uint8(148) <= 0x37) and

        // Mode field must start with valid octal
        (uint8(100) >= 0x30 and uint8(100) <= 0x37) and

        // Size field must start with valid octal or be null/space
        (uint8(124) == 0x20 or uint8(124) == 0x00 or
         (uint8(124) >= 0x30 and uint8(124) <= 0x37))
}