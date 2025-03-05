private rule DOC_Structure
{
    meta:
        description = "Detects Microsoft Office Binary DOC format"

    condition:
        uint32(0) == 0xE011CFD0 and
        uint32(4) == 0xE11AB1A1
}
