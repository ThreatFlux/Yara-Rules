private rule MP3_Structure
{
    meta:
        description = "Detects MP3 file structure"

    condition:
        uint16be(0) == 0x4944 or
        (uint16be(0) & 0xFFFE) == 0xFFFA
}

rule Detect_MP3
{
    meta:
        description = "Example rule that detects MP3 media files"

    condition:
        MP3_Structure
}
