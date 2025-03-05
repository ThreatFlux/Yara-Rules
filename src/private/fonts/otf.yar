private rule OTF_Structure
{
    meta:
        description = "Detects OpenType Font format"

    condition:
        uint32be(0) == 0x4F54544F // 'OTTO'
}