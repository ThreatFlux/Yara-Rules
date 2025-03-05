private rule VHD_Structure
{
    meta:
        description = "Detects Virtual Hard Disk format"

    strings:
        $conectix = "conectix"

    condition:
        $conectix at filesize - 512
}