private rule TTF_Structure
{
    meta:
        description = "Detects TrueType Font format"

    condition:
        uint32be(0) == 0x00010000 or
        uint32be(0) == 0x74727565 // 'true'
}