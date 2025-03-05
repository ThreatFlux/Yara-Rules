include "../../private/archives/zip.yar"

private rule DOCX_Format
{
    meta:
        description = "Detects valid, openable Word DOCX files"
        reference_files = "minimal.docx (78a3550406ecae06cedd5821ebb72a00)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "DOCX"

    strings:
        // Required DOCX structure files
        $content_types = "[Content_Types].xml"
        $rels = "_rels/.rels"
        $word_dir = "word/"
        $document_xml = "word/document.xml"
        $document_rels = "word/_rels/document.xml.rels"
        $styles = "word/styles.xml"

        // Office Open XML identifiers
        $docx_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
        $schema = "http://schemas.openxmlformats.org/wordprocessingml/2006/"

        // Required namespace declarations
        $w_namespace = "xmlns:w="
        $r_namespace = "xmlns:r="

    condition:
        // Must be a valid ZIP file
        ZIP_Structure and

        // Required basic structure
        all of ($content_types, $rels, $word_dir, $document_xml) and

        // Must have either styles or document relationships
        ($styles or $document_rels) and

        // Must have proper content type identifiers
        $docx_type and

        // Must have proper schema reference
        $schema and

        // Must have required namespaces
        all of ($w_namespace, $r_namespace) and

        // Size constraints
        filesize >= 2KB        // Minimum size for valid DOCX
}
