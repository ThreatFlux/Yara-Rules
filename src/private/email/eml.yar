private rule EML_Structure
{
    meta:
        description = "Detects EML email format"

    strings:
        $from = "From:"
        $received = "Received:"
        $date = "Date:"

    condition:
        any of them in (0..1024)
}

