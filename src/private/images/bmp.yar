private rule BMP_Structure
{
    meta:
        description = "Detects valid, viewable BMP files"
        reference_files = "1px.bmp (605c2108b543dfd42bd41d804df34f58)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "BMP"

    condition:
        // File header validation
        uint16(0) == 0x4D42           // "BM" signature

}