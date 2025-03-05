private rule SevenZ_Structure
{
    meta:
        description = "Detects valid, extractable 7Z archives"
        reference_files = "empty.7z (4839bef02498a90ec40c3420c2533fb7)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "7Z"

    condition:
        // Signature Header
        uint32(0) == 0x37375A37 and      // '7z\xBC'
        uint32(4) == 0xAFBC271C      // '\xAF\x27\x1C'

}