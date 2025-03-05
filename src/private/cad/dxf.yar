private rule DXF_Structure
{
    meta:
        description = "Detects AutoCAD DXF format"

    strings:
        $header_crlf = "0\x0dSECTION"
        $header_lf = "0\x0aSECTION"

    condition:
        any of ($header_crlf, $header_lf) at 0
}
