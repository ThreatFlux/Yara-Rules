private rule ICO_Structure
{
    meta:
        description = "Detects valid, usable ICO/CUR files"
        reference_files = "1px.ico (ed5a964e00f4a03ab201efe358667914)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "ICO/CUR"

    condition:
        // Header validation
        uint16(0) == 0x0000 and                // Reserved (must be 0)
        (uint16(2) == 0x0100 or               // ICO type
         uint16(2) == 0x0200) and             // CUR type

        // Number of images validation
        uint16(4) > 0 and                     // Must have at least one image
        uint16(4) <= 255 and                  // Max 255 images allowed

        // Directory entry validation
        (
            for any i in (0..uint16(4)-1):    // For each declared image
            (
                // Image dimensions check (1-256 pixels)
                uint8(6 + (i * 16)) != 0 and      // Width (0 means 256)
                uint8(7 + (i * 16)) != 0 and      // Height (0 means 256)

                // Color information
                uint8(8 + (i * 16)) <= 32 and     // Valid color palette size
                uint8(9 + (i * 16)) == 0 and      // Reserved must be 0

                // Valid size and offset
                uint32(14 + (i * 16)) > 0 and     // Size must be non-zero
                uint32(18 + (i * 16)) > 0 and     // Offset must be non-zero
                uint32(18 + (i * 16)) < filesize  // Offset must be within file
            )
        ) and

        // Minimum size validation
        filesize >= (6 + (uint16(4) * 16)) and    // Header + all directory entries

        // Maximum reasonable size check
        filesize < 10MB                           // Reasonable maximum size
}