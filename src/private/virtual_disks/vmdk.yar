private rule VMDK_Structure
{
    meta:
        description = "Detects VMware Virtual Disk format"

    strings:
        $header = "# Disk DescriptorFile"
        $encoding = "encoding="

    condition:
        $header at 0 and $encoding in (0..1000)
}