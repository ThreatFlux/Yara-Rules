private rule GZIP_Structure
{
    meta:
        description = "Detects valid, decompressable GZIP files"
        reference_files = "empty.gz (bfaacf2ee635cc5f746fc2c042748b0e)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "GZIP"

    condition:
        // Basic GZIP header check
        uint16(0) == 0x8B1F and        // GZIP magic number
        uint8(2) == 0x08 and           // Compression method (must be 8 for DEFLATE)

        // Valid flags check (bits 0-7)
        uint8(3) & 0xE0 == 0 and       // Reserved flags must be zero

        // Must have valid footer
        filesize >= 18 and             // Minimum GZIP size: header(10) + footer(8)

        // Check for valid GZIP trailer
        uint32(filesize-4) != 0 and    // Original file size must not be zero

        // OS type must be valid (0-13 or 255)
        uint8(9) <= 13 or uint8(9) == 255
}