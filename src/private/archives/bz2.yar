private rule BZ2_Structure
{
    meta:
        description = "Detects valid, decompressable BZ2 files"
        reference_files = "empty.bz2 (4059d198768f9f8dc9372dc1c54bc3c3)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "BZ2"

    condition:
        // Header checks
        uint16(0) == 0x5A42       // BZ magic number
    
}