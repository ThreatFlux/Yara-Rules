include "../../private/executables/native/elf.yar"

rule Known_Good_Linux_LS_Binary {
    meta:
        description = "Detects the GNU coreutils ls binary"
        author = "ThreatFlux"
        date = "2025-07-31"
        version = "1.0"
        reference = "https://www.gnu.org/software/coreutils/"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"

    strings:
        $s1 = "src/ls.c" ascii
        $s2 = "LS_COLORS environment variable used by GNU ls" ascii
        $s3 = "unparsable value for LS_COLORS environment variable" ascii

    condition:
        ELF_Structure and 2 of ($s*)
}
