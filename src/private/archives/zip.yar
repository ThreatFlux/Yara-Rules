private rule ZIP_Structure
{
    meta:
        description = "Detects valid, extractable ZIP archives"
        reference_files = "empty.zip (76cdb2bad9582d23c1f6f4d868218d6c)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "ZIP"

    condition:
        // Local file header signature
        uint32(0) == 0x04034B50 and

        // End of central directory signature must exist
        uint32(filesize-22) == 0x06054B50 and

        // Basic structural requirements for valid ZIP
        (
            // Central directory must exist
            uint32(uint32(filesize-6)) == 0x02014B50 and    // Central directory header signature

            // Size validations
            uint16(filesize-12) != 0 and    // Total number of entries must not be zero
            uint32(filesize-10) != 0 and    // Size of central directory must not be zero

            // Minimum valid ZIP size (local header + central dir + end of central dir)
            filesize >= 45
        )
}