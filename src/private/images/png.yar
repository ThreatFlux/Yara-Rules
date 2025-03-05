private rule PNG_Structure
{
    meta:
        description = "Detects valid, viewable PNG files"
        reference_files = "1px.png (73acd0b4a2391d4bbd9765aca5db19dc)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "PNG"

    condition:
        // Signature validation
        uint32be(0) == 0x89504E47 and     // PNG magic
        uint32be(4) == 0x0D0A1A0A and     // PNG magic continuation

        // IHDR chunk validation (must be first chunk)
        uint32be(8) == 0x0000000D and     // Length of IHDR must be 13
        uint32be(12) == 0x49484452 and    // "IHDR"

        // Image dimensions must be non-zero
        uint32be(16) != 0 and             // Width > 0
        uint32be(20) != 0 and             // Height > 0

        // Valid bit depth (1, 2, 4, 8, or 16)
        uint8(24) == 1 or
        uint8(24) == 2 or
        uint8(24) == 4 or
        uint8(24) == 8 or
        uint8(24) == 16 and

        // Valid color type (0, 2, 3, 4, 6)
        uint8(25) <= 6 and
        uint8(25) != 1 and
        uint8(25) != 5 and

        // Compression method must be 0
        uint8(26) == 0 and

        // Filter method must be 0
        uint8(27) == 0 and

        // Interlace method must be 0 or 1
        uint8(28) <= 1 and

        // Must end with IEND chunk
        uint32be(filesize-8) == 0x49454E44   // "IEND"
}