private rule DWG_Structure
{
    meta:
        description = "Detects AutoCAD DWG format"

    strings:
        $ac1012 = "AC1012"
        $ac1014 = "AC1014"
        $ac1015 = "AC1015"
        $ac1018 = "AC1018"
        $ac1021 = "AC1021"

    condition:
        any of them at 0
}
