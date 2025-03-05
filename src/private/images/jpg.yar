private rule JPEG_Structure
{
    meta:
        description = "Detects valid, viewable JPEG files"
        reference_files = "1px.jpg (2775f338c469b19c338c4e0ea410271c)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "JPEG"

    condition:
        // Start of Image marker
        uint16be(0) == 0xFFD8 and

        // JFIF/EXIF APP0/APP1 marker validation
        (
            // JFIF
            (uint16be(2) == 0xFFE0 and      // APP0 marker
             uint32be(6) == 0x4A464946 and  // "JFIF"
             uint16be(11) != 0) or          // version must not be 0,0

            // EXIF
            (uint16be(2) == 0xFFE1 and      // APP1 marker
             uint32be(6) == 0x45786966)     // "Exif"
        ) and

        // Start of Frame marker (one must exist)
        (
            for any i in (2..filesize-2): (
                // Baseline DCT
                uint16be(i) == 0xFFC0 or
                // Progressive DCT
                uint16be(i) == 0xFFC2
            )
        ) and

        // Must have at least one quantization table
        (
            for any i in (2..filesize-2): (
                uint16be(i) == 0xFFDB
            )
        ) and

        // Must end with End of Image marker
        uint16be(filesize-2) == 0xFFD9
}