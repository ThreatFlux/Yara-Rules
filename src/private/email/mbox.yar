private rule MBOX_Structure
{
    meta:
        description = "Detects MBOX email format"

    strings:
        $from = "From "

    condition:
        $from at 0
}
