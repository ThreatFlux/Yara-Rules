include "../private/documents/doc.yar"
include "../private/documents/docx.yar"

rule HUNT_Images_In_Office_Documents
{
    meta:
        description = "Detects images embedded within Microsoft Office documents using validated structural analysis"
        author = "ThreatFlux"
        date = "2024-01-03"
        version = "2.1"
        
        // Classification
        threat_level = "Information" 
        category = "FILE.OFFICE.EMBEDDED.IMAGE"
        tlp = "WHITE"
        
        // Analysis Context
        detection_strategy = "Multi-layered structural validation with optimized signature detection"
        performance_impact = "Low - Uses anchored checks and early termination"
        
        // File Properties
        supported_formats = "DOC, DOCX"
        min_size = "4KB"
        max_size = "50MB"
        
        // References
        ref = "https://en.wikipedia.org/wiki/Office_Open_XML"
        
    strings:
        // DOCX content markers
        $media_path = "word/media/"
        
        // OLE compound file marker
        
        // Image signatures for precise matching
        $png_sig = { 89 50 4E 47 0D 0A 1A 0A }
        $jpg_sig = { FF D8 FF }
        $gif_sig = { 47 49 46 38 }
        $bmp_sig = { 42 4D }
        
    condition:
        // Size constraints for performance optimization
        filesize > 4KB and
        
        (
            // DOCX Format Validation
            (DOCX_Format and
             (
                $media_path or // Direct media directory check
                any of ($png_sig, $jpg_sig, $gif_sig, $bmp_sig)
             )
            )
            or 
            // DOC Format Validation
            (DOC_Structure and
             uint32(512) != 0 and // Non-empty validation
             (
                // Scan for embedded images after OLE header
                $png_sig in (512..filesize) or
                $jpg_sig in (512..filesize) or
                $gif_sig in (512..filesize) or
                $bmp_sig in (512..filesize)
             )
            )
        )
}
