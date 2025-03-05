private rule RAR_Structure
{
    meta:
        description = "Detects valid RAR archives (both RAR4 and RAR5)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "RAR"
        reference_files = "empty.rar (43cb84654daeba93d348d61dd96682fb)"

    condition:
        // Header check for RAR formats
        (
            // RAR 4.x format
            (uint32be(0) == 0x52617221 and     // Rar!
             uint16be(4) == 0x1A07 and         // RAR 4 marker
             uint16(6) != 0 and                // HeaderSize must not be zero
             uint32(24) != 0) or               // File data size must not be zero

            // RAR 5.x format
            (uint32be(0) == 0x52617221 and     // Rar!
             uint32be(4) == 0x1A070100 and     // RAR 5 marker
             uint32(16) & 0x4 != 0)            // Must have ARCHIVE flag set in header flags
        ) and

        // Minimum size for a valid archive (header + minimal content)
        filesize >= 32
}