private rule TIFF_Structure
{
    meta:
        description = "Detects valid, viewable TIFF files"
        reference_files = "1px.tiff (c70a1170d3b00eb040b5ed22f2d802d3)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "TIFF"

    condition:
        // Byte order mark validation
        (
            (uint16(0) == 0x4949 and     // II (little-endian)
             uint16(2) == 0x2A00) or     // Version (42) in little-endian
            (uint16(0) == 0x4D4D and     // MM (big-endian)
             uint16(2) == 0x002A)        // Version (42) in big-endian
        ) and

        // IFD (Image File Directory) validation
        (
            // IFD offset must be valid (depends on endianness)
            (uint16(0) == 0x4949 and uint32(4) < filesize and uint32(4) >= 8) or
            (uint16(0) == 0x4D4D and uint32be(4) < filesize and uint32be(4) >= 8)
        ) and

        // Required Tags Check (using both endian possibilities)
        (
            // First check the number of directory entries
            (uint16(0) == 0x4949 and uint16(uint32(4)) > 0) or
            (uint16(0) == 0x4D4D and uint16be(uint32be(4)) > 0)
        ) and

        // File must be large enough for basic structure
        filesize >= 8 and

        // Minimum size requirement based on IFD offset
        (
            (uint16(0) == 0x4949 and filesize >= uint32(4) + 2) or
            (uint16(0) == 0x4D4D and filesize >= uint32be(4) + 2)
        )
}