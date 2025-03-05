private rule GIF_Structure
{
    meta:
        description = "Detects valid, viewable GIF files"
        reference_files = "1px.gif (2c5f182a5005cfdeec4bd4071fad0e39)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "GIF"

    condition:
        // Header validation
        uint32be(0) == 0x47494638 and              // "GIF8"
        (uint16be(4) == 0x3761 or                  // "7a" - GIF87a
         uint16be(4) == 0x3961)                // "9a" - GIF89a

}