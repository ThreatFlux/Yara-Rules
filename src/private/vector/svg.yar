private rule SVG_Structure
{
    meta:
        description = "Detects SVG file structure"

    strings:
        $svg_xml = "<?xml"
        $svg_tag = "<svg"

    condition:
        ($svg_xml at 0 and $svg_tag in (0..200)) or
        $svg_tag at 0
}
