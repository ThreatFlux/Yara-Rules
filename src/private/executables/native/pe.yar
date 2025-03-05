private rule PE_Structure
{
    meta:
        description = "Detects executable PE files (both EXE and DLL)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.3"
        file_type = "PE"
        
    condition:
        // Basic PE file structure
        uint16(0) == 0x5A4D and                    // MZ header
        uint32(uint32(0x3C)) == 0x00004550         // PE signature
}
