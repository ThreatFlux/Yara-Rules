private rule Class_Structure
{
    meta:
        description = "Detects valid, executable Java class files"
        reference_files = "Minimal.class (2a43b9c65fe45f8f2ac57d8067dfd085)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "Java Class"

    condition:
        // Magic number check
        uint32be(0) == 0xCAFEBABE and

        // Version checks
        (
            // Major version (Java version compatibility)
            uint16be(6) >= 45 and          // Minimum Java 1.1
            uint16be(6) <= 65 and          // Maximum Java 21
            // Minor version
            uint16be(4) <= 0xFFFF
        ) and

        // Constant pool validation
        uint16be(8) > 0 and                // Constant pool count must be positive

        // Access flags must be valid
        (uint16be(uint16be(8) * 2 + 8) & 0xF000) == 0 and  // Upper bits must be 0

        // Must have valid this_class index
        uint16be(uint16be(8) * 2 + 10) != 0 and

        // Minimum size for a valid class file
        filesize >= 24
}