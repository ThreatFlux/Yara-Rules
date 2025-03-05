private rule PDF_Structure
{
    meta:
        description = "Detects valid, readable PDF files"
        reference_files = "minimal.pdf (4a6f4ff8596321eea6fa482e7adbed01)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "PDF"

    strings:
        $header = "%PDF-"
        $eof_marker = "%%EOF"
        $startxref = "startxref"
        $xref = "xref"
        $trailer = "trailer"

    condition:
        // Header validation
        $header at 0 and
        uint8(5) >= 0x31 and          // Major version >= 1
        uint8(5) <= 0x37 and          // Major version <= 7
        uint8(7) == 0x2E and          // Decimal point
        uint8(8) >= 0x30 and          // Minor version >= 0
        uint8(8) <= 0x37 and          // Minor version <= 7

        // Basic structure requirements
        filesize > 32 and             // Minimum size for valid PDF
        $eof_marker in (filesize-10..filesize) and  // EOF marker near end

        // Required PDF elements
        $xref and                     // Must have cross-reference table
        $trailer and                  // Must have trailer
        $startxref and                // Must have startxref pointer

        // Basic binary check
        uint8(1) == 0x50 and         // 'P'
        uint8(2) == 0x44 and         // 'D'
        uint8(3) == 0x46             // 'F'
}