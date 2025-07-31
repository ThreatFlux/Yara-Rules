include "../../private/executables/native/elf.yar"
// Auto-generated from 456 ELF binaries in /bin
rule Known_Good_Linux___Binary {
    meta:
        description = "Track /bin/[ binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/["

    strings:
        $s1 = "Beware that parentheses need to be escaped (e.g., by backslashes) for shells." ascii // found in 1/456 binaries
        $s2 = "  FILE1 -ef FILE2   FILE1 and FILE2 have the same device and inode numbers" ascii // found in 1/456 binaries
        $s3 = "NOTE: Binary -a and -o are inherently ambiguous.  Use 'test EXPR1 && test" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_addpart_Binary {
    meta:
        description = "Track /bin/addpart binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/addpart"

    strings:
        $s1 = "Tell the kernel about the existence of a specified partition." ascii // found in 1/456 binaries
        $s2 = " %s <disk device> <partition number> <start> <length>" ascii // found in 1/456 binaries
        $s3 = "2af374cca452d2b79798736ae29c016734059e.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_apt_Binary {
    meta:
        description = "Track /bin/apt binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/apt"

    strings:
        $s1 = "searching and managing as well as querying information about packages." ascii // found in 1/456 binaries
        $s2 = "like apt-get and apt-cache, but enables options more suitable for" ascii // found in 1/456 binaries
        $s3 = "It provides the same functionality as the specialized APT tools," ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_apt_cache_Binary {
    meta:
        description = "Track /bin/apt-cache binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/apt-cache"

    strings:
        $s1 = "_ZN6FileFdC1ENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEjNS_12CompressModeEm" ascii // found in 1/456 binaries
        $s2 = "_ZN13pkgTagSection3Tag6RemoveERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE" ascii // found in 1/456 binaries
        $s3 = "displayed information may therefore be outdated if the last update was" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_apt_cdrom_Binary {
    meta:
        description = "Track /bin/apt-cdrom binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/apt-cdrom"

    strings:
        $s1 = "_ZN8pkgCdrom5IdentERNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEP14pkgCdromStatus" ascii // found in 1/456 binaries
        $s2 = "See 'man apt-cdrom' for more information about the CD-ROM auto-detection and mount point." ascii // found in 1/456 binaries
        $s3 = "No CD-ROM could be auto-detected or found using the default mount point." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_apt_config_Binary {
    meta:
        description = "Track /bin/apt-config binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/apt-config"

    strings:
        $s1 = "_ZNK13Configuration10FindVectorEPKcRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEb" ascii // found in 1/456 binaries
        $s2 = "_ZN13Configuration5ClearERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE" ascii // found in 1/456 binaries
        $s3 = "all APT tools, mainly intended for debugging and shell scripting." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_apt_get_Binary {
    meta:
        description = "Track /bin/apt-get binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/apt-get"

    strings:
        $s1 = "_Z15InstallPackagesR9CacheFileRN3APT16PackageContainerISt6vectorIN8pkgCache11PkgIteratorESaIS5_EEEEb" ascii // found in 1/456 binaries
        $s2 = "_ZNK11IndexTarget6FormatENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE" ascii // found in 1/456 binaries
        $s3 = "_ZTSN3APT16PackageContainerISt6vectorIN8pkgCache11PkgIteratorESaIS3_EEEE" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_apt_mark_Binary {
    meta:
        description = "Track /bin/apt-mark binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/apt-mark"

    strings:
        $s1 = "_ZN3APT25VersionContainerInterface15FromCommandLineEPS0_R12pkgCacheFilePPKcNS_14CacheSetHelper11VerS" ascii // found in 1/456 binaries
        $s2 = "_ZTSN3APT16VersionContainerISt6vectorIN8pkgCache11VerIteratorESaIS3_EEEE" ascii // found in 1/456 binaries
        $s3 = "N3APT16VersionContainerISt6vectorIN8pkgCache11VerIteratorESaIS3_EEEE" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_arch_Binary {
    meta:
        description = "Track /bin/arch binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/arch"

    strings:
        $s1 = "11e5b436f01b2447aef922d20ef885c6ae5702.debug" ascii // found in 1/456 binaries
        $s2 = "Print machine architecture." ascii // found in 1/456 binaries
        $s3 = "G(H;G0s/H" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_b2sum_Binary {
    meta:
        description = "Track /bin/b2sum binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/b2sum"

    strings:
        $s1 = "e15b2773f151d5ac4112756233754736f8fe92.debug" ascii // found in 1/456 binaries
        $s2 = "Samuel Neves" ascii // found in 1/456 binaries
        $s3 = "RFC 7693" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_base32_Binary {
    meta:
        description = "Track /bin/base32 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/base32"

    strings:
        $s1 = "b5238c7cd26c6d5b494b61f3ae4d7f96d8974e.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_base64_Binary {
    meta:
        description = "Track /bin/base64 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/base64"

    strings:
        $s1 = "1ce20eb3a22cba18521f4a86c723567047b723.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_basename_Binary {
    meta:
        description = "Track /bin/basename binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/basename"

    strings:
        $s1 = "  -a, --multiple       support multiple arguments and treat each as a NAME" ascii // found in 1/456 binaries
        $s2 = "  -z, --zero           end each output line with NUL, not newline" ascii // found in 1/456 binaries
        $s3 = "  -s, --suffix=SUFFIX  remove a trailing SUFFIX; implies -a" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_basenc_Binary {
    meta:
        description = "Track /bin/basenc binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/basenc"

    strings:
        $s1 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#" ascii // found in 1/456 binaries
        $s2 = "                        when encoding, input length must be a multiple of 4;" ascii // found in 1/456 binaries
        $s3 = "                        when decoding, input length must be a multiple of 5" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_bash_Binary {
    meta:
        description = "Track /bin/bash binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/bash"

    strings:
        $s1 = ">???????@@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBCCDDEEEEEFFFFFFFFFFFGGGGGGGGHHHHIIIIIIIIJJJ" ascii // found in 1/456 binaries
        $s2 = "complete [-abcdefgjksuv] [-pr] [-DEI] [-o option] [-A action] [-G globpat] [-W wordlist] [-F functio" ascii // found in 1/456 binaries
        $s3 = "bind [-lpsvPSVX] [-m keymap] [-f filename] [-q name] [-u name] [-r keyseq] [-x keyseq:shell-command]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_bison_Binary {
    meta:
        description = "Track /bin/bison binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/bison"

    strings:
        $s1 = "STREQ (default_reductions, \"most\") || (STREQ (default_reductions, \"consistent\") && default_reduction" ascii // found in 1/456 binaries
        $s2 = "=>??@@@@@@@@@@@@@@@@A@@@@@@@@@BBCCCCCCCDDEECGFHFIFFJJJJKKLLMMNNOOOPQQQRRSTTUUUVVVWWXXYYYZZ[[\\\\\\^]___" ascii // found in 1/456 binaries
        $s3 = "Productions leading up to the conflict state found.  Still finding a possible unifying counterexampl" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_brz_Binary {
    meta:
        description = "Track /bin/brz binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/brz"

    strings:
        $s1 = "/build/rustc-41eSBy/rustc-1.75.0+dfsg0ubuntu1/library/core/src/str/pattern.rsOsmessageErrorCustomerr" ascii // found in 1/456 binaries
        $s2 = "library/std/src/env.rspermission deniedconnection refusednetwork unreachableconnection abortednot co" ascii // found in 1/456 binaries
        $s3 = "attempted to fetch exception but none was setFailed to initialize nul terminated exception name/usr/" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_bunzip2_Binary {
    meta:
        description = "Track /bin/bunzip2 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/bunzip2"

    strings:
        $s1 = "   This program is free software; you can redistribute it and/or modify" ascii // found in 3/456 binaries
        $s2 = "   it under the terms set out in the LICENSE file, which is included" ascii // found in 3/456 binaries
        $s3 = "              as `bzcat', default action is to decompress to stdout." ascii // found in 3/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_busctl_Binary {
    meta:
        description = "Track /bin/busctl binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/busctl"

    strings:
        $s1 = "     --augment-creds=BOOL  Extend credential data with data read from /proc/$PID" ascii // found in 1/456 binaries
        $s2 = "  -j                       Same as --json=pretty on tty, --json=short otherwise" ascii // found in 1/456 binaries
        $s3 = "     --watch-bind=BOOL     Wait for bus AF_UNIX socket to be bound in the file" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_bzcat_Binary {
    meta:
        description = "Track /bin/bzcat binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/bzcat"

    strings:
        $s1 = "   This program is free software; you can redistribute it and/or modify" ascii // found in 3/456 binaries
        $s2 = "   it under the terms set out in the LICENSE file, which is included" ascii // found in 3/456 binaries
        $s3 = "              as `bzcat', default action is to decompress to stdout." ascii // found in 3/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_bzip2_Binary {
    meta:
        description = "Track /bin/bzip2 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/bzip2"

    strings:
        $s1 = "   This program is free software; you can redistribute it and/or modify" ascii // found in 3/456 binaries
        $s2 = "   it under the terms set out in the LICENSE file, which is included" ascii // found in 3/456 binaries
        $s3 = "              as `bzcat', default action is to decompress to stdout." ascii // found in 3/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_bzip2recover_Binary {
    meta:
        description = "Track /bin/bzip2recover binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/bzip2recover"

    strings:
        $s1 = "%s: supplied filename is suspiciously (>= %d chars) long.  Bye!" ascii // found in 1/456 binaries
        $s2 = "bzip2recover 1.0.8: extracts blocks from damaged .bz2 files." ascii // found in 1/456 binaries
        $s3 = "%s: BZ_MAX_HANDLED_BLOCKS in bzip2recover.c, and recompile." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_cat_Binary {
    meta:
        description = "Track /bin/cat binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/cat"

    strings:
        $s1 = "  -v, --show-nonprinting   use ^ and M- notation, except for LFD and TAB" ascii // found in 1/456 binaries
        $s2 = "  %s f - g  Output f's contents, then standard input, then g's contents." ascii // found in 1/456 binaries
        $s3 = "  -b, --number-nonblank    number nonempty output lines, overrides -n" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ccache_Binary {
    meta:
        description = "Track /bin/ccache binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ccache"

    strings:
        $s1 = "*ZZN7httplib6detail21write_content_chunkedIZNKS_10ClientImpl27write_content_with_providerERNS_6Strea" ascii // found in 1/456 binaries
        $s2 = "*ZN7httplib6detail21write_content_chunkedIZNKS_10ClientImpl27write_content_with_providerERNS_6Stream" ascii // found in 1/456 binaries
        $s3 = "constexpr const U& tl::expected<T, E>::operator*() const & [with U = std::__cxx11::basic_string<char" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ccache_swig3_0_Binary {
    meta:
        description = "Track /bin/ccache-swig3.0 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ccache-swig3.0"

    strings:
        $s1 = "-M <maxsize>            set maximum size of cache (use G, M or K)" ascii // found in 1/456 binaries
        $s2 = "CCACHE_OUTFILES env variable already set or could not be set" ascii // found in 1/456 binaries
        $s3 = "%s, a compiler cache including support for SWIG. Version %s" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_chage_Binary {
    meta:
        description = "Track /bin/chage binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/chage"

    strings:
        $s1 = "  -d, --lastday LAST_DAY        set date of last password change to LAST_DAY" ascii // found in 1/456 binaries
        $s2 = "  -E, --expiredate EXPIRE_DATE  set account expiration date to EXPIRE_DATE" ascii // found in 1/456 binaries
        $s3 = "  -m, --mindays MIN_DAYS        set minimum number of days before password" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_chattr_Binary {
    meta:
        description = "Track /bin/chattr binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/chattr"

    strings:
        $s1 = "Usage: %s [-RVf] [-+=aAcCdDeijPsStTuFx] [-p project] [-v version] files..." ascii // found in 1/456 binaries
        $s2 = "Couldn't allocate path variable in chattr_dir_proc" ascii // found in 1/456 binaries
        $s3 = "fd511a3b9f7121a338da7bbf9089f051bf9183.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_chcon_Binary {
    meta:
        description = "Track /bin/chcon binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/chcon"

    strings:
        $s1 = "With --reference, change the security context of each FILE to that of RFILE." ascii // found in 1/456 binaries
        $s2 = "      --reference=RFILE  use RFILE's security context rather than specifying" ascii // found in 1/456 binaries
        $s3 = "  -l, --range=RANGE      set range RANGE in the target security context" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_chfn_Binary {
    meta:
        description = "Track /bin/chfn binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/chfn"

    strings:
        $s1 = "  -o, --other OTHER_INFO        change user's other GECOS information" ascii // found in 1/456 binaries
        $s2 = "  -u, --help                    display this help message and exit" ascii // found in 1/456 binaries
        $s3 = "  -w, --work-phone WORK_PHONE   change user's office phone number" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_chgrp_Binary {
    meta:
        description = "Track /bin/chgrp binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/chgrp"

    strings:
        $s1 = "      --reference=RFILE  use RFILE's group rather than specifying a GROUP." ascii // found in 1/456 binaries
        $s2 = "  %s -hR staff /u  Change the group of /u and subfiles to \"staff\"." ascii // found in 1/456 binaries
        $s3 = "With --reference, change the group of each FILE to that of RFILE." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_chmod_Binary {
    meta:
        description = "Track /bin/chmod binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/chmod"

    strings:
        $s1 = "      --reference=RFILE  use RFILE's mode instead of specifying MODE values." ascii // found in 1/456 binaries
        $s2 = "Each MODE is of the form '[ugoa]*([-+=]([rwxXst]*|[ugo]))+|[-+=][0-7]+'." ascii // found in 1/456 binaries
        $s3 = "Rcfvr::w::x::X::s::t::u::g::o::a::,::+::=::0::1::2::3::4::5::6::7::" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_choom_Binary {
    meta:
        description = "Track /bin/choom binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/choom"

    strings:
        $s1 = " -n, --adjust <num>     specify the adjust score value" ascii // found in 1/456 binaries
        $s2 = "pid %d's OOM score adjust value changed from %d to %d" ascii // found in 1/456 binaries
        $s3 = " %1$s [options] -n number [--] command [args...]]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_chown_Binary {
    meta:
        description = "Track /bin/chown binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/chown"

    strings:
        $s1 = "                         its current owner and/or group match those specified" ascii // found in 1/456 binaries
        $s2 = "With --reference, change the owner and group of each FILE to those of RFILE." ascii // found in 1/456 binaries
        $s3 = "                         here.  Either may be omitted, in which case a match" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_chrt_Binary {
    meta:
        description = "Track /bin/chrt binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/chrt"

    strings:
        $s1 = "--sched-{runtime,deadline,period} options are supported for SCHED_DEADLINE only" ascii // found in 1/456 binaries
        $s2 = "unsupported priority value for the policy: %d: see --max for valid range" ascii // found in 1/456 binaries
        $s3 = "pid %d's current runtime/deadline/period parameters: %ju/%ju/%ju" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_chsh_Binary {
    meta:
        description = "Track /bin/chsh binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/chsh"

    strings:
        $s1 = "  -s, --shell SHELL             new login shell for the user account" ascii // found in 1/456 binaries
        $s2 = "ff2da747a874ef391637dec11b051e9be4030d.debug" ascii // found in 1/456 binaries
        $s3 = "You may not change the shell for '%s'." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_cksum_Binary {
    meta:
        description = "Track /bin/cksum binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/cksum"

    strings:
        $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/Copyright %s %d Free Software Founda" ascii // found in 1/456 binaries
        $s2 = "      --untagged        create a reversed style checksum, without digest type" ascii // found in 1/456 binaries
        $s3 = "  -a, --algorithm=TYPE  select the digest type to use.  See DIGEST below." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_clear_Binary {
    meta:
        description = "Track /bin/clear binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/clear"

    strings:
        $s1 = "32c1d82603f7ea7e95b70f96aa58f7f52cb1c9.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_clear_console_Binary {
    meta:
        description = "Track /bin/clear_console binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/clear_console"

    strings:
        $s1 = "-V --version   display version information and exit" ascii // found in 1/456 binaries
        $s2 = "-h --help      display this help text and exit" ascii // found in 1/456 binaries
        $s3 = "224ad22db7f542454cacfaf1fc60c5a4a36d34.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_cmake_Binary {
    meta:
        description = "Track /bin/cmake binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/cmake"

    strings:
        $s1 = "COMPILE_FEATURESCMAKE_CURRENT_SOCMAKE_CURRENT_BICMAKE_HOST_SYSTECMAKE_HOST_WIN32CMAKE_HOST_LINUXCMAK" ascii // found in 1/456 binaries
        $s2 = "Fortran_PREPROCEAIX_EXPORT_ALL_SCMAKE_PLATFORM_H_HAS_INSTALLNAMEABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" ascii // found in 1/456 binaries
        $s3 = "];GRAPHVIZ_GRAPH_NGRAPHVIZ_GRAPH_HGRAPHVIZ_NODE_PRGRAPHVIZ_EXECUTAGRAPHVIZ_STATIC_GRAPHVIZ_SHARED_GR" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_cmp_Binary {
    meta:
        description = "Track /bin/cmp binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/cmp"

    strings:
        $s1 = "-l, --verbose              output byte numbers and differing byte values" ascii // found in 1/456 binaries
        $s2 = "-i, --ignore-initial=SKIP         skip first SKIP bytes of both inputs" ascii // found in 1/456 binaries
        $s3 = "SKIP values may be followed by the following multiplicative suffixes:" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_comm_Binary {
    meta:
        description = "Track /bin/comm binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/comm"

    strings:
        $s1 = "  -3                      suppress column 3 (lines that appear in both files)" ascii // found in 1/456 binaries
        $s2 = "      --nocheck-order     do not check that the input is correctly sorted" ascii // found in 1/456 binaries
        $s3 = "      --check-order       check that the input is correctly sorted, even" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_cp_Binary {
    meta:
        description = "Track /bin/cp binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/cp"

    strings:
        $s1 = "warning: behavior of -n is non-portable and may change in future; use --update=none instead" ascii // found in 1/456 binaries
        $s2 = "                                 (overrides a -u or previous -i option). See also" ascii // found in 1/456 binaries
        $s3 = "  -n, --no-clobber             do not overwrite an existing file and do not fail" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_cpack_Binary {
    meta:
        description = "Track /bin/cpack binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/cpack"

    strings:
        $s1 = "COMPILE_FEATURESCMAKE_CURRENT_BICMAKE_HOST_SYSTECMAKE_HOST_WIN32CMAKE_HOST_LINUXCMAKE_MAJOR_VERSCMAK" ascii // found in 1/456 binaries
        $s2 = "Fortran_PREPROCEAIX_EXPORT_ALL_SCMAKE_PLATFORM_H_HAS_INSTALLNAMEGLOBAL_DEPENDS_DPENDS_DEBUG_MODEGLOB" ascii // found in 1/456 binaries
        $s3 = "];GRAPHVIZ_GRAPH_NGRAPHVIZ_GRAPH_HGRAPHVIZ_NODE_PRGRAPHVIZ_EXECUTAGRAPHVIZ_STATIC_GRAPHVIZ_SHARED_GR" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_csplit_Binary {
    meta:
        description = "Track /bin/csplit binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/csplit"

    strings:
        $s1 = "Output pieces of FILE separated by PATTERN(s) to files 'xx00', 'xx01', ...," ascii // found in 1/456 binaries
        $s2 = "  {INTEGER}          repeat the previous pattern specified number of times" ascii // found in 1/456 binaries
        $s3 = "  {*}                repeat the previous pattern as many times as possible" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ctest_Binary {
    meta:
        description = "Track /bin/ctest binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ctest"

    strings:
        $s1 = "COMPILE_FEATURESCMAKE_CURRENT_BICMAKE_HOST_SYSTECMAKE_HOST_WIN32CMAKE_HOST_LINUXCMAKE_MAJOR_VERSCMAK" ascii // found in 1/456 binaries
        $s2 = "DEPRECATION_ERRODeprecation erroDEPRECATION_WARNDeprecation warnadditionalModulecompletionTriggerigg" ascii // found in 1/456 binaries
        $s3 = "called with incorrect number of ber of argumentsCTEST_CHECKOUT_CToo many argumensource directory not" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_curl_Binary {
    meta:
        description = "Track /bin/curl binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/curl"

    strings:
        $s1 = "Binary output can mess up your terminal. Use \"--output -\" to tell curl to output it to your terminal" ascii // found in 1/456 binaries
        $s2 = "Invalid character is found in given range. A specified range MUST have only digits in 'start'-'stop'" ascii // found in 1/456 binaries
        $s3 = "Using --anyauth or --proxy-anyauth with upload from stdin involves a big risk of it not working. Use" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_cut_Binary {
    meta:
        description = "Track /bin/cut binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/cut"

    strings:
        $s1 = "      --complement        complement the set of selected bytes, characters" ascii // found in 1/456 binaries
        $s2 = "  -f, --fields=LIST       select only these fields;  also print any line" ascii // found in 1/456 binaries
        $s3 = "                            that contains no delimiter character, unless" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_cvtsudoers_Binary {
    meta:
        description = "Track /bin/cvtsudoers binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/cvtsudoers"

    strings:
        $s1 = "usage: %s [-ehMpV] [-b dn] [-c conf_file ] [-d deftypes] [-f output_format] [-i input_format] [-I in" ascii // found in 1/456 binaries
        $s2 = "ABBCCDDDDDDDDDDDDDDEEFFGGHHHHHIIIJKKLLLLLMMNOOOOPPQQRRSTUVWXYZ[\\]]^^^^^___________`aaaaaaaaaaabbbbbb" ascii // found in 1/456 binaries
        $s3 = "The umask specified in sudoers will override the user's, even if it is more permissive" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dash_Binary {
    meta:
        description = "Track /bin/dash binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dash"

    strings:
        $s1 = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" ascii // found in 1/456 binaries
        $s2 = "Usage: kill [-s sigspec | -signum | -sigspec] [pid | job]... or" ascii // found in 1/456 binaries
        $s3 = "Maximum function recursion depth (%d) reached" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_date_Binary {
    meta:
        description = "Track /bin/date binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/date"

    strings:
        $s1 = "  %:::z  numeric time zone with : to necessary precision (e.g., -04, +05:30)" ascii // found in 1/456 binaries
        $s2 = "  --resolution               output the available resolution of timestamps" ascii // found in 1/456 binaries
        $s3 = "  -u, --utc, --universal     print or set Coordinated Universal Time (UTC)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dbus_cleanup_sockets_Binary {
    meta:
        description = "Track /bin/dbus-cleanup-sockets binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dbus-cleanup-sockets"

    strings:
        $s1 = "Warning: giving up on socket %s after several retries; unable to determine socket's status" ascii // found in 1/456 binaries
        $s2 = "Cleaned up %d sockets in %s; %d sockets are still in use; %d in unknown state" ascii // found in 1/456 binaries
        $s3 = "Unable to determine state of some sockets, retrying in 2 seconds" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dbus_daemon_Binary {
    meta:
        description = "Track /bin/dbus-daemon binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dbus-daemon"

    strings:
        $s1 = "dbus-daemon [--version] [--session] [--system] [--config-file=FILE] [--print-address[=DESCRIPTOR]] [" ascii // found in 1/456 binaries
        $s2 = "An AppArmor policy prevents this sender from sending this message to this recipient; type=\"%s\", send" ascii // found in 1/456 binaries
        $s3 = "Monitoring connection %s (%s) is not allowed to send messages; closing it. Please fix the monitor to" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dbus_monitor_Binary {
    meta:
        description = "Track /bin/dbus-monitor binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dbus-monitor"

    strings:
        $s1 = "Usage: %s [--system | --session | --address ADDRESS] [--monitor | --profile | --pcap | --binary ] [w" ascii // found in 1/456 binaries
        $s2 = "dbus-monitor: unable to enable new-style monitoring, your dbus-daemon is too old. Falling back to ea" ascii // found in 1/456 binaries
        $s3 = "dbus-monitor: unable to enable new-style monitoring: %s: \"%s\". Falling back to eavesdropping." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dbus_run_session_Binary {
    meta:
        description = "Track /bin/dbus-run-session binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dbus-run-session"

    strings:
        $s1 = "--config-file=FILENAME     pass to dbus-daemon instead of --session" ascii // found in 1/456 binaries
        $s2 = "--dbus-daemon=BINARY       run BINARY instead of dbus-daemon" ascii // found in 1/456 binaries
        $s3 = "/usr/lib/debug/.dwz/x86_64-linux-gnu/dbus-daemon.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dbus_send_Binary {
    meta:
        description = "Track /bin/dbus-send binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dbus-send"

    strings:
        $s1 = "Usage: %s [--help] [--system | --session | --bus=ADDRESS | --peer=ADDRESS] [--sender=NAME] [--dest=N" ascii // found in 1/456 binaries
        $s2 = "\"--peer\" and \"--bus\" may not be used with \"--system\" or \"--session\"" ascii // found in 1/456 binaries
        $s3 = "Must use org.mydomain.Interface.Method notation, no dot in \"%s\"" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dbus_update_activation_environment_Binary {
    meta:
        description = "Track /bin/dbus-update-activation-environment binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dbus-update-activation-environment"

    strings:
        $s1 = "%1$s: update environment variables that will be set for D-Bus" ascii // found in 1/456 binaries
        $s2 = "%s: error: --all cannot be used with VAR or VAR=VAL arguments" ascii // found in 1/456 binaries
        $s3 = "    Add specified variables to D-Bus activation environment." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dbus_uuidgen_Binary {
    meta:
        description = "Track /bin/dbus-uuidgen binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dbus-uuidgen"

    strings:
        $s1 = "Usage: %s [--ensure[=FILENAME]] [--get[=FILENAME]]" ascii // found in 1/456 binaries
        $s2 = "ba707fb766b063ea6b06160dbf595011124e12.debug" ascii // found in 1/456 binaries
        $s3 = "Can't specify both --get and --ensure" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dd_Binary {
    meta:
        description = "Track /bin/dd binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dd"

    strings:
        $s1 = "  append    append mode (makes sense only for output; conv=notrunc suggested)" ascii // found in 1/456 binaries
        $s2 = "  bs=BYTES        read and write up to BYTES bytes at a time (default: 512);" ascii // found in 1/456 binaries
        $s3 = "offset too large: cannot truncate to a length of seek=%ld (%td-byte) blocks" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_delpart_Binary {
    meta:
        description = "Track /bin/delpart binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/delpart"

    strings:
        $s1 = "Tell the kernel to forget about a specified partition." ascii // found in 1/456 binaries
        $s2 = "67cbf0b356a4792e2aafc608d4dbdf8028879f.debug" ascii // found in 1/456 binaries
        $s3 = " %s <disk device> <partition number>" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_delv_Binary {
    meta:
        description = "Track /bin/delv binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/delv"

    strings:
        $s1 = "        . initial-key 257 3 8 \"AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3" ascii // found in 1/456 binaries
        $s2 = "# which are included as part of BIND 9.  The only trust anchors it contains" ascii // found in 1/456 binaries
        $s3 = "# Servers being set up for the first time can use the contents of this file" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_derb_Binary {
    meta:
        description = "Track /bin/derb binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/derb"

    strings:
        $s1 = "%s: Error: don't specify an encoding (-e) when writing to stdout (-c)." ascii // found in 1/456 binaries
        $s2 = " [ -s, --sourcedir source ] [ -d, --destdir destination ]" ascii // found in 1/456 binaries
        $s3 = " [ -v, --verbose ] [ -e, --encoding encoding ] [ --bom ]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_df_Binary {
    meta:
        description = "Track /bin/df binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/df"

    strings:
        $s1 = "      --no-sync         do not invoke sync before getting usage info (default)" ascii // found in 1/456 binaries
        $s2 = "  -a, --all             include pseudo, duplicate, inaccessible file systems" ascii // found in 1/456 binaries
        $s3 = "                               or print all fields if FIELD_LIST is omitted." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_diff_Binary {
    meta:
        description = "Track /bin/diff binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/diff"

    strings:
        $s1 = "-u, -U NUM, --unified[=NUM]   output NUM (default 3) lines of unified context" ascii // found in 1/456 binaries
        $s2 = "    --suppress-blank-empty    suppress space or tab before empty output lines" ascii // found in 1/456 binaries
        $s3 = "    --palette=PALETTE    the colors to use when --color is active; PALETTE is" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_diff3_Binary {
    meta:
        description = "Track /bin/diff3 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/diff3"

    strings:
        $s1 = "-3, --easy-only             like -e, but incorporate only nonoverlapping changes" ascii // found in 1/456 binaries
        $s2 = "-x, --overlap-only          like -e, but incorporate only overlapping changes" ascii // found in 1/456 binaries
        $s3 = "The default output format is a somewhat human-readable representation of" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dig_Binary {
    meta:
        description = "Track /bin/dig binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dig"

    strings:
        $s1 = "                 +[no]http-plain-get      (Use GET instead of default POST method while using plain " ascii // found in 1/456 binaries
        $s2 = "                 +[no]https-get      (Use GET instead of default POST method while using HTTPS)" ascii // found in 1/456 binaries
        $s3 = "                 +[no]tls-ca[=file]  (Enable remote server's TLS certificate validation)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dir_Binary {
    meta:
        description = "Track /bin/dir binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dir"

    strings:
        $s1 = "3257691e9356c0e41dcba2efa1f0837ebdbeec.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dircolors_Binary {
    meta:
        description = "Track /bin/dircolors binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dircolors"

    strings:
        $s1 = "For details on the format of these files, run 'dircolors --print-database'." ascii // found in 1/456 binaries
        $s2 = "If FILE is specified, read it to determine which colors to use for which" ascii // found in 1/456 binaries
        $s3 = "  -b, --sh, --bourne-shell    output Bourne shell code to set LS_COLORS" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dirmngr_Binary {
    meta:
        description = "Track /bin/dirmngr binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dirmngr"

    strings:
        $s1 = "NOTE: DirMngr is now a proper part of %s.  The configuration and other directory names changed.  Ple" ascii // found in 1/456 binaries
        $s2 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890@!\"#$%&'()*+,-./:;<=>?[\\]^_{|}~" ascii // found in 1/456 binaries
        $s3 = "ISVALID [--only-ocsp] [--force-default-responder] <certificate_id> [<certificate_fpr>]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dirmngr_client_Binary {
    meta:
        description = "Track /bin/dirmngr-client binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dirmngr-client"

    strings:
        $s1 = "Usage: dirmngr-client [options] [certfile|pattern] (-h for help)" ascii // found in 1/456 binaries
        $s2 = "The process returns 0 if the certificate is valid, 1 if it is" ascii // found in 1/456 binaries
        $s3 = "Test an X.509 certificate against a CRL or do an OCSP check" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dirname_Binary {
    meta:
        description = "Track /bin/dirname binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dirname"

    strings:
        $s1 = "removed; if NAME contains no /'s, output '.' (meaning the current directory)." ascii // found in 1/456 binaries
        $s2 = "Output each NAME with its last non-slash component and trailing slashes" ascii // found in 1/456 binaries
        $s3 = "  -z, --zero     end each output line with NUL, not newline" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dmesg_Binary {
    meta:
        description = "Track /bin/dmesg binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dmesg"

    strings:
        $s1 = "--raw can be used together with --level or --facility only when reading messages from /dev/kmsg" ascii // found in 1/456 binaries
        $s2 = " -p, --force-prefix          force timestamp output on each line of multi-line messages" ascii // found in 1/456 binaries
        $s3 = " -T, --ctime                 show human-readable timestamp (may be inaccurate!)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dpkg_Binary {
    meta:
        description = "Track /bin/dpkg binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dpkg"

    strings:
        $s1 = "not enough privileges to change root directory with --force-not-root, consider using --force-script-" ascii // found in 1/456 binaries
        $s2 = "tarobject ti->name='%s' mode=%lo owner=%u:%u type=%d(%c) ti->linkname='%s' namenode='%s' flags=%o in" ascii // found in 1/456 binaries
        $s3 = "while removing %.250s, unable to remove directory '%.250s': %s - directory may be a mount point?" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dpkg_deb_Binary {
    meta:
        description = "Track /bin/dpkg-deb binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dpkg-deb"

    strings:
        $s1 = "  -Z<type>                         Set the compression type used when building." ascii // found in 1/456 binaries
        $s2 = "maintainer script '%.50s' has bad permissions %03lo (must be >=0555 and <=0775)" ascii // found in 1/456 binaries
        $s3 = "  -S<strategy>                     Set the compression strategy when building." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dpkg_divert_Binary {
    meta:
        description = "Track /bin/dpkg-divert binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dpkg-divert"

    strings:
        $s1 = "diverting file '%s' from an Essential package with rename is dangerous, use --no-rename" ascii // found in 1/456 binaries
        $s2 = "please specify --no-rename explicitly, the default will change to --rename in 1.20.x" ascii // found in 1/456 binaries
        $s3 = "  --package <package>      name of the package whose copy of <file> will not" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dpkg_query_Binary {
    meta:
        description = "Track /bin/dpkg-query binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dpkg-query"

    strings:
        $s1 = "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend" ascii // found in 1/456 binaries
        $s2 = "  --load-avail                     Use available file on --show and --list." ascii // found in 1/456 binaries
        $s3 = "Use dpkg --contents (= dpkg-deb --contents) to list archive files contents." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dpkg_split_Binary {
    meta:
        description = "Track /bin/dpkg-split binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dpkg-split"

    strings:
        $s1 = "there are several versions of part %d - at least '%.250s' and '%.250s'" ascii // found in 1/456 binaries
        $s2 = "                                     <package>_<version>_<arch>.deb)." ascii // found in 1/456 binaries
        $s3 = "header is too long, making part too long; the package name or version" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dpkg_statoverride_Binary {
    meta:
        description = "Track /bin/dpkg-statoverride binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dpkg-statoverride"

    strings:
        $s1 = "an override for '%s' already exists, but --force specified so will be ignored" ascii // found in 1/456 binaries
        $s2 = "  --admindir <directory>   set the directory with the statoverride file." ascii // found in 1/456 binaries
        $s3 = "                           add a new <path> entry into the database." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_dpkg_trigger_Binary {
    meta:
        description = "Track /bin/dpkg-trigger binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/dpkg-trigger"

    strings:
        $s1 = "  --check-supported                Check if the running dpkg supports triggers." ascii // found in 1/456 binaries
        $s2 = "  --no-act                         Just test - don't actually change anything." ascii // found in 1/456 binaries
        $s3 = "  --no-await                       No package needs to await the processing." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_du_Binary {
    meta:
        description = "Track /bin/du binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/du"

    strings:
        $s1 = "      --apparent-size   print apparent sizes rather than device usage; although" ascii // found in 1/456 binaries
        $s2 = "  -h, --human-readable  print sizes in human readable format (e.g., 1K 234M 2G)" ascii // found in 1/456 binaries
        $s3 = "  -d, --max-depth=N     print the total for a directory (or file, with --all)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_echo_Binary {
    meta:
        description = "Track /bin/echo binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/echo"

    strings:
        $s1 = "  -E             disable interpretation of backslash escapes (default)" ascii // found in 1/456 binaries
        $s2 = "  -e             enable interpretation of backslash escapes" ascii // found in 1/456 binaries
        $s3 = "If -e is in effect, the following sequences are recognized:" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_env_Binary {
    meta:
        description = "Track /bin/env binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/env"

    strings:
        $s1 = "      --default-signal[=SIG]  reset handling of SIG signal(s) to the default" ascii // found in 1/456 binaries
        $s2 = "      --ignore-signal[=SIG]   set handling of SIG signal(s) to do nothing" ascii // found in 1/456 binaries
        $s3 = "  -v, --debug          print verbose information for each processing step" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_envsubst_Binary {
    meta:
        description = "Track /bin/envsubst binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/envsubst"

    strings:
        $s1 = "of the environment variables that are referenced in SHELL-FORMAT, one per line." ascii // found in 1/456 binaries
        $s2 = "with references to environment variables of the form $VARIABLE or ${VARIABLE}" ascii // found in 1/456 binaries
        $s3 = "  -v, --variables             output the variables occurring in SHELL-FORMAT" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_errno_Binary {
    meta:
        description = "Track /bin/errno binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/errno"

    strings:
        $s1 = "Usage: errno [-lsS] [--list] [--search] [--search-all-locales] [keyword]" ascii // found in 1/456 binaries
        $s2 = "1035596aac771805e85c5134df6313e5c89637.debug" ascii // found in 1/456 binaries
        $s3 = "ERROR: Can't execute locale -a: %d: %s" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_expand_Binary {
    meta:
        description = "Track /bin/expand binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/expand"

    strings:
        $s1 = "Convert tabs in each FILE to spaces, writing to standard output." ascii // found in 1/456 binaries
        $s2 = "  -i, --initial    do not convert tabs after non blanks" ascii // found in 1/456 binaries
        $s3 = "  -t, --tabs=N     have tabs N characters apart, not 8" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_expiry_Binary {
    meta:
        description = "Track /bin/expiry binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/expiry"

    strings:
        $s1 = "  -f, --force                   force password change if the user's password" ascii // found in 1/456 binaries
        $s2 = "  -c, --check                   check the user's password expiration" ascii // found in 1/456 binaries
        $s3 = "7091adbf45dce3b3189b56c7a1ee4047684e71.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_expr_Binary {
    meta:
        description = "Track /bin/expr binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/expr"

    strings:
        $s1 = "Exit status is 0 if EXPRESSION is neither null nor 0, 1 if EXPRESSION is null" ascii // found in 1/456 binaries
        $s2 = "  index STRING CHARS         index in STRING where any CHARS is found, or 0" ascii // found in 1/456 binaries
        $s3 = "                               keyword like 'match' or an operator like '/'" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_factor_Binary {
    meta:
        description = "Track /bin/factor binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/factor"

    strings:
        $s1 = "(&&FFHN\\ZfdDBBB4,$,420**.442<>@BD<846462.0*,(88:8JLHH@<BH68<D>@8<@FHFNPRHB8:6..<<HHTNPPBB6<,0*.8@BFB" ascii // found in 1/456 binaries
        $s2 = "\"$ $\" $$$&($$$\",*(&.,02(*****($,200*.,4.(**,***20,.68@8.0680.*00240422.00**$.002.0:8><B@B>8@44,,,.*," ascii // found in 1/456 binaries
        $s3 = "  -h, --exponents   print repeated factors in form p^e unless e is 1" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_faillog_Binary {
    meta:
        description = "Track /bin/faillog binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/faillog"

    strings:
        $s1 = "  -l, --lock-secs SEC           after failed login lock account for SEC seconds" ascii // found in 1/456 binaries
        $s2 = "  -t, --time DAYS               display faillog records more recent than DAYS" ascii // found in 1/456 binaries
        $s3 = "  -u, --user LOGIN/RANGE        display faillog record or maintains failure" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_fallocate_Binary {
    meta:
        description = "Track /bin/fallocate binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/fallocate"

    strings:
        $s1 = " -i, --insert-range   insert a hole at range, shifting existing data" ascii // found in 1/456 binaries
        $s2 = " -x, --posix          use posix_fallocate(3) instead of fallocate(2)" ascii // found in 1/456 binaries
        $s3 = " -p, --punch-hole     replace a range with a hole (implies -n)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_false_Binary {
    meta:
        description = "Track /bin/false binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/false"

    strings:
        $s1 = "b7823545f8cd8749aa55809a923b4b88700acf.debug" ascii // found in 1/456 binaries
        $s2 = "Exit with a status code indicating failure." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_fc_cache_Binary {
    meta:
        description = "Track /bin/fc-cache binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/fc-cache"

    strings:
        $s1 = "usage: %s [-EfrsvVh] [-y SYSROOT] [--error-on-no-fonts] [--force|--really-force] [--sysroot=SYSROOT]" ascii // found in 1/456 binaries
        $s2 = "  -f, --force              scan directories with apparently valid caches" ascii // found in 1/456 binaries
        $s3 = "  -E, --error-on-no-fonts  raise an error if no fonts in a directory" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_fc_cat_Binary {
    meta:
        description = "Track /bin/fc-cat binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/fc-cat"

    strings:
        $s1 = "usage: %s [-rv] [--recurse] [--verbose] [*-%s.cache-9|directory]..." ascii // found in 1/456 binaries
        $s2 = "  -r, --recurse        recurse into subdirectories" ascii // found in 1/456 binaries
        $s3 = "be2c8cea6702bb6d99bd8b998f0f0d4b29dc39.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_fc_conflist_Binary {
    meta:
        description = "Track /bin/fc-conflist binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/fc-conflist"

    strings:
        $s1 = "Show the ruleset files information on the system" ascii // found in 1/456 binaries
        $s2 = "3f343f95883d0083a2279f75c95df930556b70.debug" ascii // found in 1/456 binaries
        $s3 = "usage: %s [-Vh] [--version] [--help]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_fc_list_Binary {
    meta:
        description = "Track /bin/fc-list binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/fc-list"

    strings:
        $s1 = "usage: %s [-vbqVh] [-f FORMAT] [--verbose] [--brief] [--format=FORMAT] [--quiet] [--version] [--help" ascii // found in 1/456 binaries
        $s2 = "  -q, --quiet          suppress all normal output, exit 1 if no fonts matched" ascii // found in 1/456 binaries
        $s3 = "de69818398ccceb56e94b520e9923c9b77817e.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_fc_match_Binary {
    meta:
        description = "Track /bin/fc-match binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/fc-match"

    strings:
        $s1 = "usage: %s [-savbVh] [-f FORMAT] [--sort] [--all] [--verbose] [--brief] [--format=FORMAT] [--version]" ascii // found in 1/456 binaries
        $s2 = "  -a, --all            display unpruned sorted list of matches" ascii // found in 1/456 binaries
        $s3 = "  -s, --sort           display sorted list of matches" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_fc_pattern_Binary {
    meta:
        description = "Track /bin/fc-pattern binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/fc-pattern"

    strings:
        $s1 = "usage: %s [-cdVh] [-f FORMAT] [--config] [--default] [--verbose] [--format=FORMAT] [--version] [--he" ascii // found in 1/456 binaries
        $s2 = "  -d, --default        perform default substitution on pattern" ascii // found in 1/456 binaries
        $s3 = "  -c, --config         perform config substitution on pattern" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_fc_query_Binary {
    meta:
        description = "Track /bin/fc-query binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/fc-query"

    strings:
        $s1 = "usage: %s [-bVh] [-i index] [-f FORMAT] [--index index] [--brief] [--format FORMAT] [--version] [--h" ascii // found in 1/456 binaries
        $s2 = "  -b, --brief          display font pattern briefly" ascii // found in 1/456 binaries
        $s3 = "Query font files and print resulting pattern(s)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_fc_scan_Binary {
    meta:
        description = "Track /bin/fc-scan binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/fc-scan"

    strings:
        $s1 = "usage: %s [-bcVh] [-f FORMAT] [-y SYSROOT] [--brief] [--format FORMAT] [--version] [--help] font-fil" ascii // found in 1/456 binaries
        $s2 = "  -y, --sysroot=SYSROOT  prepend SYSROOT to all paths for scanning" ascii // found in 1/456 binaries
        $s3 = "Scan font files and directories, and print resulting pattern(s)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_fc_validate_Binary {
    meta:
        description = "Track /bin/fc-validate binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/fc-validate"

    strings:
        $s1 = "usage: %s [-Vhv] [-i index] [-l LANG] [--index index] [--lang LANG] [--verbose] [--version] [--help]" ascii // found in 1/456 binaries
        $s2 = "%s:%d Missing %d glyph(s) to satisfy the coverage for %s language" ascii // found in 1/456 binaries
        $s3 = "  -l, --lang=LANG      set LANG instead of current locale" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_find_Binary {
    meta:
        description = "Track /bin/find binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/find"

    strings:
        $s1 = "The current directory is included in the PATH environment variable, which is insecure in combination" ascii // found in 1/456 binaries
        $s2 = "warning: you have specified the global option %s after the argument %s, but global options are not p" ascii // found in 1/456 binaries
        $s3 = "warning: you have specified a mode pattern %s (which is equivalent to /000). The meaning of -perm /0" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_findmnt_Binary {
    meta:
        description = "Track /bin/findmnt binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/findmnt"

    strings:
        $s1 = "options --target and --source can't be used together with command line element that is not an option" ascii // found in 1/456 binaries
        $s2 = " -y, --shell            use column names to be usable as shell variable identifiers" ascii // found in 1/456 binaries
        $s3 = " -b, --bytes            print sizes in bytes rather than in human readable format" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_flock_Binary {
    meta:
        description = "Track /bin/flock binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/flock"

    strings:
        $s1 = " -E, --conflict-exit-code <number>  exit code after conflict or timeout" ascii // found in 1/456 binaries
        $s2 = " -c, --command <command>  run a single command string through the shell" ascii // found in 1/456 binaries
        $s3 = " -o, --close              close file descriptor before running command" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_fmt_Binary {
    meta:
        description = "Track /bin/fmt binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/fmt"

    strings:
        $s1 = "  -t, --tagged-paragraph    indentation of first line different from second" ascii // found in 1/456 binaries
        $s2 = "                              reattaching the prefix to reformatted lines" ascii // found in 1/456 binaries
        $s3 = "  -u, --uniform-spacing     one space between words, two after sentences" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_fold_Binary {
    meta:
        description = "Track /bin/fold binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/fold"

    strings:
        $s1 = "Wrap input lines in each FILE, writing to standard output." ascii // found in 1/456 binaries
        $s2 = "  -b, --bytes         count bytes rather than columns" ascii // found in 1/456 binaries
        $s3 = "  -w, --width=WIDTH   use WIDTH columns instead of 80" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_free_Binary {
    meta:
        description = "Track /bin/free binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/free"

    strings:
        $s1 = "               total        used        free      shared     buffers       cache   available" ascii // found in 1/456 binaries
        $s2 = "               total        used        free      shared  buff/cache   available" ascii // found in 1/456 binaries
        $s3 = " -l, --lohi          show detailed low and high memory statistics" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_fsnotifywait_Binary {
    meta:
        description = "Track /bin/fsnotifywait binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/fsnotifywait"

    strings:
        $s1 = "73cefceb8deb2e123ba651aba3b1d7e0bbc8ea.debug" ascii // found in 1/456 binaries
        $s2 = "Setting up filesystem watches." ascii // found in 1/456 binaries
        $s3 = "fsnotifywait" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_fsnotifywatch_Binary {
    meta:
        description = "Track /bin/fsnotifywatch binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/fsnotifywatch"

    strings:
        $s1 = "b4356693206f7d5812a6fe0c1dba3fb80b76c8.debug" ascii // found in 1/456 binaries
        $s2 = "Setting up filesystem watch on %s" ascii // found in 1/456 binaries
        $s3 = "fsnotifywatch" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_funzip_Binary {
    meta:
        description = "Track /bin/funzip binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/funzip"

    strings:
        $s1 = "Extracts to stdout the gzip file or first zip entry of stdin or the given file." ascii // found in 1/456 binaries
        $s2 = "funzip warning: zipfile has more than one entry--rest ignored" ascii // found in 1/456 binaries
        $s3 = "first entry not deflated or stored--cannot unpack" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gapplication_Binary {
    meta:
        description = "Track /bin/gapplication binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gapplication"

    strings:
        $s1 = "List the installed D-Bus activatable applications (by .desktop files)" ascii // found in 1/456 binaries
        $s2 = "Application identifier in D-Bus format (eg: org.example.viewer)" ascii // found in 1/456 binaries
        $s3 = "Optional parameter to the action invocation, in GVariant format" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gawk_Binary {
    meta:
        description = "Track /bin/gawk binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gawk"

    strings:
        $s1 = ";<<===>>>>>????@@@@AABCDEDFFGGGGGGGGGHGIGGGGGJGGKGLGMGGGGGGGGGNGGOPPQQRRRRSSSTUUUVWWWWWXYXXZXX[[\\\\]]" ascii // found in 1/456 binaries
        $s2 = "MNNNNNOOOOOOPPPQQQRRRSSSSSSSTUUUUVVXWZY[\\\\]]]^^__________`````a``cbdbbbeefffgghhhhhhiijjklkmmnnooppq" ascii // found in 1/456 binaries
        $s3 = "until [[filename:]N|function] - execute until program reaches a different line or line N within curr" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gdbus_Binary {
    meta:
        description = "Track /bin/gdbus binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gdbus"

    strings:
        $s1 = "Timeout to wait for before exiting with an error (seconds); 0 for no timeout (default)" ascii // found in 1/456 binaries
        $s2 = "Warning: Introspection data indicates %d parameters but more was passed" ascii // found in 1/456 binaries
        $s3 = "Service to activate before waiting for the other one (well-known name)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_genbrk_Binary {
    meta:
        description = "Track /bin/genbrk binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/genbrk"

    strings:
        $s1 = "_ZN6icu_7422RuleBasedBreakIteratorC1ERKNS_13UnicodeStringER11UParseErrorR10UErrorCode" ascii // found in 1/456 binaries
        $s2 = "If the rule file does not have a Unicode signature byte sequence, it is assumed" ascii // found in 1/456 binaries
        $s3 = "createRuleBasedBreakIterator: ICU Error \"%s\"  at line %d, column %d" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gencat_Binary {
    meta:
        description = "Track /bin/gencat binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gencat"

    strings:
        $s1 = "If INPUT-FILE is -, input is read from standard input.  If OUTPUT-FILE" ascii // found in 1/456 binaries
        $s2 = "wbuf[(wbufsize - outlen) / sizeof (wchar_t) - 1] == L'\\0'" ascii // found in 1/456 binaries
        $s3 = "Create C header file NAME containing symbol definitions" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gencfu_Binary {
    meta:
        description = "Track /bin/gencfu binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gencfu"

    strings:
        $s1 = "Read in Unicode confusable character definitions and write out the binary data" ascii // found in 1/456 binaries
        $s2 = "gencfu: uspoof_openFromSource error \"%s\"  at file %s, line %d, column %d" ascii // found in 1/456 binaries
        $s3 = "Usage: %s [-v] [-options] -r confusablesRules.txt -o output-file" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gencnval_Binary {
    meta:
        description = "Track /bin/gencnval binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gencnval"

    strings:
        $s1 = "%s:%d: warning: Tag \"%s\" was added to the list of standards because it was not declared at beginning" ascii // found in 1/456 binaries
        $s2 = "warning(line %d): alias %s contains an \"=\". Options are parsed at run-time and do not need to be in " ascii // found in 1/456 binaries
        $s3 = "warning(line %d): alias %s contains a \",\". Options are parsed at run-time and do not need to be in t" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gendict_Binary {
    meta:
        description = "Track /bin/gendict binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gendict"

    strings:
        $s1 = "gendict: got failure of type %s while serializing, if U_ILLEGAL_ARGUMENT_ERROR possibly due to dupli" ascii // found in 1/456 binaries
        $s2 = "you must provide a transformation for a bytes trie, and must not provide one for a uchars trie!" ascii // found in 1/456 binaries
        $s3 = "_ZN6icu_7416BytesTrieBuilder16buildStringPieceE22UStringTrieBuildOptionR10UErrorCode" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_genrb_Binary {
    meta:
        description = "Track /bin/genrb binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/genrb"

    strings:
        $s1 = "<xliff version = \"1.1\" xmlns='urn:oasis:names:tc:xliff:document:1.1' xmlns:xsi='http://www.w3.org/20" ascii // found in 1/456 binaries
        $s2 = "_ZN6icu_7416CollationBuilder13parseAndBuildERKNS_13UnicodeStringEPKhPNS_19CollationRuleParser8Import" ascii // found in 1/456 binaries
        $s3 = "_ZN6icu_7419CollationDataWriter14writeTailoringERKNS_18CollationTailoringERKNS_17CollationSettingsEP" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_getconf_Binary {
    meta:
        description = "Track /bin/getconf binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/getconf"

    strings:
        $s1 = "Get the configuration value for variable VAR, or for variable PATH_VAR" ascii // found in 1/456 binaries
        $s2 = "for path PATH.  If SPEC is given, give values for compilation" ascii // found in 1/456 binaries
        $s3 = "Usage: %s [-v specification] variable_name [pathname]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_getent_Binary {
    meta:
        description = "Track /bin/getent binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/getent"

    strings:
        $s1 = "do not filter out unsupported IPv4/IPv6 addresses (with ahosts*)" ascii // found in 1/456 binaries
        $s2 = "fa9e98c161243424f2eb395c1e036f20a576c9.debug" ascii // found in 1/456 binaries
        $s3 = "Get entries from administrative database." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_getopt_Binary {
    meta:
        description = "Track /bin/getopt binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/getopt"

    strings:
        $s1 = " -s, --shell <shell>           set quoting conventions to those of <shell>" ascii // found in 1/456 binaries
        $s2 = " -a, --alternative             allow long options starting with single -" ascii // found in 1/456 binaries
        $s3 = " -n, --name <progname>         the name under which errors are reported" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gettext_Binary {
    meta:
        description = "Track /bin/gettext binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gettext"

    strings:
        $s1 = "But it does not simply copy its arguments to stdout.  Instead those messages" ascii // found in 1/456 binaries
        $s2 = "When used with the -s option the program behaves like the 'echo' command." ascii // found in 1/456 binaries
        $s3 = "  -d, --domain=TEXTDOMAIN   retrieve translated messages from TEXTDOMAIN" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gio_Binary {
    meta:
        description = "Track /bin/gio binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gio"

    strings:
        $s1 = "standard::name,standard::type,standard::is-hidden,standard::is-symlink,standard::symlink-target,stan" ascii // found in 1/456 binaries
        $s2 = "Restore a file from trash to its original location (possibly recreating the directory)" ascii // found in 1/456 binaries
        $s3 = "Launch an application from a desktop file, passing optional filename arguments to it." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_git_Binary {
    meta:
        description = "Track /bin/git binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/git"

    strings:
        $s1 = "[a-zA-Z][a-zA-Z0-9_]*|\\.([Ee][Qq]|[Nn][Ee]|[Gg][TtEe]|[Ll][TtEe]|[Tt][Rr][Uu][Ee]|[Ff][Aa][Ll][Ss][E" ascii // found in 1/456 binaries
        $s2 = "[a-zA-Z][a-zA-Z0-9_]*|\\.([Ee][Qq]|[Nn][Ee]|[Gg][TtEe]|[Ll][TtEe]|[Tt][Rr][Uu][Ee]|[Ff][Aa][Ll][Ss][E" ascii // found in 1/456 binaries
        $s3 = "git submodule [--quiet] update [--init [--filter=<filter-spec>]] [--remote] [-N|--no-fetch] [-f|--fo" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_git_lfs_Binary {
    meta:
        description = "Track /bin/git-lfs binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/git-lfs"

    strings:
        $s1 = "birkenesoddtangentinglobodoes-itcouldbeworldishangrilamdongnairkitapps-audibleasecuritytacticsxn--0t" ascii // found in 1/456 binaries
        $s2 = "startTheWorld: inconsistent mp->nextpruntime: unexpected SPWRITE function all goroutines are asleep " ascii // found in 1/456 binaries
        $s3 = "attempting pure SSH protocol connectionpure SSH protocol connection failed: %shttp: putIdleConn: kee" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_git_shell_Binary {
    meta:
        description = "Track /bin/git-shell binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/git-shell"

    strings:
        $s1 = "hint: ~/git-shell-commands should exist and have read and execute access." ascii // found in 1/456 binaries
        $s2 = "could not determine user's home directory; HOME is unset" ascii // found in 1/456 binaries
        $s3 = "1c04caba25202c10cc3886f60b66c9ad4671f1.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gpasswd_Binary {
    meta:
        description = "Track /bin/gpasswd binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gpasswd"

    strings:
        $s1 = "Unable to generate a salt from setting \"%s\", check your settings in ENCRYPT_METHOD and the correspon" ascii // found in 1/456 binaries
        $s2 = "                                set the list of administrators for GROUP" ascii // found in 1/456 binaries
        $s3 = "  -R, --restrict                restrict access to GROUP to its members" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gpg_Binary {
    meta:
        description = "Track /bin/gpg binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gpg"

    strings:
        $s1 = "Normally, an email address is associated with a single key.  However, people sometimes generate a ne" ascii // found in 1/456 binaries
        $s2 = "policy == _tofu_GET_POLICY_ERROR || policy == TOFU_POLICY_NONE || policy == TOFU_POLICY_AUTO || poli" ascii // found in 1/456 binaries
        $s3 = "Warning: if you think you've seen more signatures by this key and these user ids, then this key migh" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gpg_agent_Binary {
    meta:
        description = "Track /bin/gpg-agent binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gpg-agent"

    strings:
        $s1 = "You have not entered a passphrase - this is in general a bad idea!%0APlease confirm that you do not " ascii // found in 1/456 binaries
        $s2 = "Please enter a passphrase to protect the received secret key%%0A   %s%%0A   %s%%0Awithin gpg-agent's" ascii // found in 1/456 binaries
        $s3 = "no LISTEN_FDS or LISTEN_FDNAMES environment variables found in --supervised mode (assuming 1 active " ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gpg_connect_agent_Binary {
    meta:
        description = "Track /bin/gpg-connect-agent binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gpg-connect-agent"

    strings:
        $s1 = "/open VAR FILE MODE    Open FILE and assign the file descriptor to VAR." ascii // found in 1/456 binaries
        $s2 = "/definqfile NAME FILE  Use content of FILE for inquiries with NAME." ascii // found in 1/456 binaries
        $s3 = "/definq NAME VAR       Use content of VAR for inquiries with NAME." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gpgconf_Binary {
    meta:
        description = "Track /bin/gpgconf binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gpgconf"

    strings:
        $s1 = "empty string argument for option %s is currently not allowed.  Please report this!" ascii // found in 1/456 binaries
        $s2 = "string argument for option %s must begin with a quote (\") character" ascii // found in 1/456 binaries
        $s3 = "flag \"default\" may not be combined with a value at '%s', line %d" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gpgparsemail_Binary {
    meta:
        description = "Track /bin/gpgparsemail binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gpgparsemail"

    strings:
        $s1 = "usage: gpgparsemail [OPTION] [FILE] (try --help for more information)" ascii // found in 1/456 binaries
        $s2 = "line number %u too long or last line not terminated" ascii // found in 1/456 binaries
        $s3 = "note: ignoring nested PGP/MIME or S/MIME signature" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gpgsm_Binary {
    meta:
        description = "Track /bin/gpgsm binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gpgsm"

    strings:
        $s1 = "  offline     - Returns OK if the connection is in offline mode.  always-trust- Returns OK if the co" ascii // found in 1/456 binaries
        $s2 = "To complete this certificate request please enter the passphrase for the key you just created once m" ascii // found in 1/456 binaries
        $s3 = "after checking the fingerprint, you may want to add it manually to the list of trusted certificates." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gpgsplit_Binary {
    meta:
        description = "Track /bin/gpgsplit binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gpgsplit"

    strings:
        $s1 = "Usage: gpgsplit [options] [files] (-h for help)" ascii // found in 1/456 binaries
        $s2 = "9f8e49749b9a8bb025b4d016a6bd3bd1bf8474.debug" ascii // found in 1/456 binaries
        $s3 = "write to stdout and don't actually split" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gpgtar_Binary {
    meta:
        description = "Track /bin/gpgtar binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gpgtar"

    strings:
        $s1 = "%s: extended header record larger than total extended header data" ascii // found in 1/456 binaries
        $s2 = "%s: header block %llu is corrupt (size=%llu type=%d nrec=%llu)" ascii // found in 1/456 binaries
        $s3 = "error reading '%s': premature EOF (size of last record: %zu)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gpgv_Binary {
    meta:
        description = "Track /bin/gpgv binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gpgv"

    strings:
        $s1 = "preferred-email-encoding@pgp.com[invalid image]" ascii // found in 1/456 binaries
        $s2 = "ybndrfg8ejkmcpqxot1uwisza345h769parse_symkeyenc" ascii // found in 1/456 binaries
        $s3 = "51f75db59ce67bcbd368b215f64b28b3b35621.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_grep_Binary {
    meta:
        description = "Track /bin/grep binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/grep"

    strings:
        $s1 = "      --include=GLOB        search only files that match GLOB (a file pattern)" ascii // found in 1/456 binaries
        $s2 = "  -L, --files-without-match  print only names of FILEs with no selected lines" ascii // found in 1/456 binaries
        $s3 = "  -U, --binary              do not strip CR characters at EOL (MSDOS/Windows)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gresource_Binary {
    meta:
        description = "Track /bin/gresource binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gresource"

    strings:
        $s1 = "  PATH      An (optional) resource path (may be partial)" ascii // found in 1/456 binaries
        $s2 = "  details                   List resources with details" ascii // found in 1/456 binaries
        $s3 = "  sections                  List resource sections" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_groups_Binary {
    meta:
        description = "Track /bin/groups binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/groups"

    strings:
        $s1 = "Print group memberships for each USERNAME or, if no USERNAME is specified, for" ascii // found in 1/456 binaries
        $s2 = "the current process (which may differ if the groups database has changed)." ascii // found in 1/456 binaries
        $s3 = "abf5cc5418e52c3ce42e622361b99a52c18af8.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gsettings_Binary {
    meta:
        description = "Track /bin/gsettings binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gsettings"

    strings:
        $s1 = "  reset-recursively         Reset all values in a given schema" ascii // found in 1/456 binaries
        $s2 = "  list-recursively          List keys and values, recursively" ascii // found in 1/456 binaries
        $s3 = "  describe                  Queries the description of a key" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_gzip_Binary {
    meta:
        description = "Track /bin/gzip binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/gzip"

    strings:
        $s1 = "%s: warning: GZIP environment variable is deprecated; use an alias or script" ascii // found in 1/456 binaries
        $s2 = "      --synchronous synchronous output (safer if system crashes, but slower)" ascii // found in 1/456 binaries
        $s3 = "This is free software.  You may redistribute copies of it under the terms of" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_hardlink_Binary {
    meta:
        description = "Track /bin/hardlink binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/hardlink"

    strings:
        $s1 = " -m, --maximize             maximize the hardlink count, remove the file with" ascii // found in 1/456 binaries
        $s2 = "     --skip-reflinks        skip already cloned files (enabled on --reflink)" ascii // found in 1/456 binaries
        $s3 = " -t, --ignore-time          ignore timestamps (when testing for equality)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_head_Binary {
    meta:
        description = "Track /bin/head binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/head"

    strings:
        $s1 = "  -n, --lines=[-]NUM       print the first NUM lines instead of the first %d;" ascii // found in 1/456 binaries
        $s2 = "  -c, --bytes=[-]NUM       print the first NUM bytes of each file;" ascii // found in 1/456 binaries
        $s3 = "  -v, --verbose            always print headers giving file names" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_host_Binary {
    meta:
        description = "Track /bin/host binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/host"

    strings:
        $s1 = "       -N changes the number of dots allowed before root lookup is done" ascii // found in 1/456 binaries
        $s2 = "Usage: host [-aCdilrTvVw] [-c class] [-N ndots] [-t type] [-W time]" ascii // found in 1/456 binaries
        $s3 = "            [-R number] [-m flag] [-p port] hostname [server]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_hostid_Binary {
    meta:
        description = "Track /bin/hostid binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/hostid"

    strings:
        $s1 = "Print the numeric identifier (in hexadecimal) for the current host." ascii // found in 1/456 binaries
        $s2 = "1c547956e0a69624ac774366ec3a34f3c071e8.debug" ascii // found in 1/456 binaries
        $s3 = "gethostid" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_hostname_Binary {
    meta:
        description = "Track /bin/hostname binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/hostname"

    strings:
        $s1 = "       {yp,nis,}domainname {nisdomain|-F file}  set NIS domain name (from file)" ascii // found in 1/456 binaries
        $s2 = "    -F, --file             read host name or NIS domain name from given file" ascii // found in 1/456 binaries
        $s3 = "   This command can get or set the host name or the NIS domain name. You can" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_hostnamectl_Binary {
    meta:
        description = "Track /bin/hostnamectl binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/hostnamectl"

    strings:
        $s1 = "Hint: use --transient option when /etc/machine-info or /etc/hostname cannot be modified (e.g. locate" ascii // found in 1/456 binaries
        $s2 = "Hint: static hostname is already set, so the specified transient hostname will not be used." ascii // found in 1/456 binaries
        $s3 = "  deployment [NAME]      Get/set deployment environment for host" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_iconv_Binary {
    meta:
        description = "Track /bin/iconv binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/iconv"

    strings:
        $s1 = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" ascii // found in 1/456 binaries
        $s2 = "The following list contains all the coded character sets known.  This does" ascii // found in 1/456 binaries
        $s3 = "not necessarily mean that all combinations of these names can be used for" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_icuexportdata_Binary {
    meta:
        description = "Track /bin/icuexportdata binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/icuexportdata"

    strings:
        $s1 = "-m or --mode        mode: currently only 'uprops', 'ucase', and 'norm', but more may be added" ascii // found in 1/456 binaries
        $s2 = "_ZN6icu_7411Normalizer211getInstanceEPKcS2_19UNormalization2ModeR10UErrorCode" ascii // found in 1/456 binaries
        $s3 = "icuexportdata version %s, ICU tool to dump data files for external consumers" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_icuinfo_Binary {
    meta:
        description = "Track /bin/icuinfo binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/icuinfo"

    strings:
        $s1 = " -K         or  --cleanup          - Call u_cleanup() before exiting (will attempt to unload plugins" ascii // found in 1/456 binaries
        $s2 = " -v                                - Print version and configuration information about ICU" ascii // found in 1/456 binaries
        $s3 = "If no arguments are given, the tool will print ICU version and configuration information." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_id_Binary {
    meta:
        description = "Track /bin/id binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/id"

    strings:
        $s1 = "  -r, --real     print the real ID instead of the effective ID, with -ugG" ascii // found in 1/456 binaries
        $s2 = "  -z, --zero     delimit entries with NUL characters, not whitespace;" ascii // found in 1/456 binaries
        $s3 = "Warning: user %s is in more groups than system's configured maximum." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ifdata_Binary {
    meta:
        description = "Track /bin/ifdata binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ifdata"

    strings:
        $s1 = " %20[^:]:%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu" ascii // found in 1/456 binaries
        $s2 = "7360fc1ec0d468bbf3abda4c0a7ef17af15a77.debug" ascii // found in 1/456 binaries
        $s3 = "Reports interface existence via return code" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ifne_Binary {
    meta:
        description = "Track /bin/ifne binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ifne"

    strings:
        $s1 = "fee20660e2daa395fad7c7afbc78166d848335.debug" ascii // found in 1/456 binaries
        $s2 = "Usage: ifne [-n] command [args]" ascii // found in 1/456 binaries
        $s3 = "Write error" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_infocmp_Binary {
    meta:
        description = "Track /bin/infocmp binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/infocmp"

    strings:
        $s1 = "Usage: infocmp [options] [-A directory] [-B directory] [termname...]" ascii // found in 1/456 binaries
        $s2 = "File comparison needs exactly two file arguments." ascii // found in 1/456 binaries
        $s3 = "%s in file 1 (%s) has %d matches in file 2 (%s):" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_inotifywait_Binary {
    meta:
        description = "Track /bin/inotifywait binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/inotifywait"

    strings:
        $s1 = "65bdf5b7737441e6e0b69e94c126bdbf78db3d.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_inotifywatch_Binary {
    meta:
        description = "Track /bin/inotifywatch binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/inotifywatch"

    strings:
        $s1 = "093cde611a75ccd199ba58e0825fb0543bfe51.debug" ascii // found in 1/456 binaries
        $s2 = "inotifywatch" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_install_Binary {
    meta:
        description = "Track /bin/install binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/install"

    strings:
        $s1 = "the --compare (-C) option is ignored when you specify a mode with non-permission bits" ascii // found in 1/456 binaries
        $s2 = "  -m, --mode=MODE     set permission mode (as in chmod), instead of rwxr-xr-x" ascii // found in 1/456 binaries
        $s3 = "  -p, --preserve-timestamps   apply access/modification times of SOURCE files" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ionice_Binary {
    meta:
        description = "Track /bin/ionice binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ionice"

    strings:
        $s1 = " -u, --uid <uid>...     act on already running processes owned by these users" ascii // found in 1/456 binaries
        $s2 = " -n, --classdata <num>  priority (0..7) in the specified scheduling class," ascii // found in 1/456 binaries
        $s3 = " -P, --pgid <pgrp>...   act on already running processes in these groups" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ipcmk_Binary {
    meta:
        description = "Track /bin/ipcmk binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ipcmk"

    strings:
        $s1 = " -S, --semaphore <number> create semaphore array with <number> elements" ascii // found in 1/456 binaries
        $s2 = " -p, --mode <mode>        permission for the resource (default is 0644)" ascii // found in 1/456 binaries
        $s3 = " -M, --shmem <size>       create shared memory segment of size <size>" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ipcrm_Binary {
    meta:
        description = "Track /bin/ipcrm binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ipcrm"

    strings:
        $s1 = " -a, --all[=shm|msg|sem]    remove all (in the specified category)" ascii // found in 1/456 binaries
        $s2 = " -M, --shmem-key <key>      remove shared memory segment by key" ascii // found in 1/456 binaries
        $s3 = " -m, --shmem-id <id>        remove shared memory segment by id" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ipcs_Binary {
    meta:
        description = "Track /bin/ipcs binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ipcs"

    strings:
        $s1 = " -i, --id <id>  print details on resource identified by <id>" ascii // found in 1/456 binaries
        $s2 = " -p, --pid         show PIDs of creator and last operator" ascii // found in 1/456 binaries
        $s3 = "------ Shared Memory Attach/Detach/Change Times --------" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ischroot_Binary {
    meta:
        description = "Track /bin/ischroot binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ischroot"

    strings:
        $s1 = "  -f, --default-false return false if detection fails" ascii // found in 1/456 binaries
        $s2 = "  -t, --default-true  return true if detection fails" ascii // found in 1/456 binaries
        $s3 = "2291abfea4f19d8026730eee0de9e88bbfdcbe.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_isutf8_Binary {
    meta:
        description = "Track /bin/isutf8 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/isutf8"

    strings:
        $s1 = "After a first byte between E1 and EC, expecting the 2nd byte between 80 and BF." ascii // found in 1/456 binaries
        $s2 = "After a first byte between E1 and EC, expecting the 3rd byte between 80 and BF." ascii // found in 1/456 binaries
        $s3 = "After a first byte between C2 and DF, expecting a 2nd byte between 80 and BF" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_join_Binary {
    meta:
        description = "Track /bin/join binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/join"

    strings:
        $s1 = "                           I.e., missing fields specified with '-12jo' options" ascii // found in 1/456 binaries
        $s2 = "  -a FILENUM             also print unpairable lines from file FILENUM, where" ascii // found in 1/456 binaries
        $s3 = "                           FILENUM is 1 or 2, corresponding to FILE1 or FILE2" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_journalctl_Binary {
    meta:
        description = "Track /bin/journalctl binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/journalctl"

    strings:
        $s1 = "New keys have been generated for host %s%s%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%0" ascii // found in 1/456 binaries
        $s2 = "Journal file %s has sealing enabled but verification key has not been passed using --verify-key=." ascii // found in 1/456 binaries
        $s3 = "/var/log/journal/%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x/fss.tmp.XXXXXX" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_jq_Binary {
    meta:
        description = "Track /bin/jq binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/jq"

    strings:
        $s1 = "--build=x86_64-linux-gnu --prefix=/usr '--includedir=${prefix}/include' '--mandir=${prefix}/share/ma" ascii // found in 1/456 binaries
        $s2 = "      --raw-output0         implies -r and output NUL after each output;" ascii // found in 1/456 binaries
        $s3 = "      --indent n            use n spaces for indentation (max 7 spaces);" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_kbxutil_Binary {
    meta:
        description = "Track /bin/kbxutil binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/kbxutil"

    strings:
        $s1 = "record number of \"--to\" is lower than \"--from\" one" ascii // found in 1/456 binaries
        $s2 = "Usage: kbxutil [options] [files] (-h for help)" ascii // found in 1/456 binaries
        $s3 = "[blob larger than length - output truncated]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_kernel_install_Binary {
    meta:
        description = "Track /bin/kernel-install binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/kernel-install"

    strings:
        $s1 = "Too many arguments specified. 'kernel-install remove' takes only kernel version. Ignoring residual a" ascii // found in 1/456 binaries
        $s2 = "Kernel image not installed to '%s', requiring manual kernel image path specification." ascii // found in 1/456 binaries
        $s3 = "  kernel-install [OPTIONS...] add [[[KERNEL-VERSION] KERNEL-IMAGE] [INITRD ...]]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_kill_Binary {
    meta:
        description = "Track /bin/kill binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/kill"

    strings:
        $s1 = " -l, --list=[<signal>]  list all signal names, or convert one to a name" ascii // found in 1/456 binaries
        $s2 = " -q, --queue <value>    integer value to be sent with the signal" ascii // found in 1/456 binaries
        $s3 = " -L, --table            list all signal names in a nice table" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_last_Binary {
    meta:
        description = "Track /bin/last binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/last"

    strings:
        $s1 = " -x, --system         display system shutdown entries and run level changes" ascii // found in 1/456 binaries
        $s2 = "     --time-format <format>  show timestamps in the specified <format>:" ascii // found in 1/456 binaries
        $s3 = " -i, --ip             display IP numbers in numbers-and-dots notation" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_lastlog_Binary {
    meta:
        description = "Track /bin/lastlog binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/lastlog"

    strings:
        $s1 = "  -S, --set                     set lastlog record to current time (usable only with -u)" ascii // found in 1/456 binaries
        $s2 = "  -C, --clear                   clear lastlog record of an user (usable only with -u)" ascii // found in 1/456 binaries
        $s3 = "  -t, --time DAYS               print only lastlog records more recent than DAYS" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_lckdo_Binary {
    meta:
        description = "Track /bin/lckdo binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/lckdo"

    strings:
        $s1 = " -t - test for lock existence (just prints pid if any with -q)" ascii // found in 1/456 binaries
        $s2 = " -W sec - the same as -w but wait not more than sec seconds" ascii // found in 1/456 binaries
        $s3 = " -E nnn - set the fd# to keep open in -e case (implies -e)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_link_Binary {
    meta:
        description = "Track /bin/link binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/link"

    strings:
        $s1 = "Call the link function to create a link named FILE2 to an existing FILE1." ascii // found in 1/456 binaries
        $s2 = "b01bd6b09d1ab9ed7030c28f8d3c92f1d27aed.debug" ascii // found in 1/456 binaries
        $s3 = "cannot create link %s to %s" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ln_Binary {
    meta:
        description = "Track /bin/ln binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ln"

    strings:
        $s1 = "      --backup[=CONTROL]      make a backup of each existing destination file" ascii // found in 1/456 binaries
        $s2 = "  -r, --relative              with -s, create links relative to link location" ascii // found in 1/456 binaries
        $s3 = "                                directories (note: will probably fail due to" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_locale_Binary {
    meta:
        description = "Track /bin/locale binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/locale"

    strings:
        $s1 = "locale: %-15.15s archive: /usr/lib/locale/locale-archive" ascii // found in 1/456 binaries
        $s2 = "warning: The LOCPATH variable is set to \"%s\"" ascii // found in 1/456 binaries
        $s3 = "7d7567a868bd7de90186ef33d8ac9cdc514bc7.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_locale_check_Binary {
    meta:
        description = "Track /bin/locale-check binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/locale-check"

    strings:
        $s1 = "Check that the various locale-related environment variables contain" ascii // found in 1/456 binaries
        $s2 = "values that can be set. Output shell that can be passed to eval to" ascii // found in 1/456 binaries
        $s3 = "set any invalid environment variables to DEFAULT_LOCALE" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_localectl_Binary {
    meta:
        description = "Track /bin/localectl binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/localectl"

    strings:
        $s1 = "Warning: Settings on kernel command line override system locale settings in /etc/locale.conf." ascii // found in 1/456 binaries
        $s2 = "  list-keymaps             Show known virtual console keyboard mappings" ascii // found in 1/456 binaries
        $s3 = "                           Show known X11 keyboard mapping variants" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_localedef_Binary {
    meta:
        description = "Track /bin/localedef binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/localedef"

    strings:
        $s1 = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" ascii // found in 1/456 binaries
        $s2 = "%s: value of field `int_curr_symbol' does not correspond to a valid name in ISO 4217 [--no-warnings=" ascii // found in 1/456 binaries
        $s3 = "%s: byte sequence of first character of range is not lower than that of the last character" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_logger_Binary {
    meta:
        description = "Track /bin/logger binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/logger"

    strings:
        $s1 = "     --rfc5424[=<snip>]   use the syslog protocol (the default for remote);" ascii // found in 1/456 binaries
        $s2 = "     --prio-prefix        look for a prefix on every line read from stdin" ascii // found in 1/456 binaries
        $s3 = "                          print connection errors when using Unix sockets" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_login_Binary {
    meta:
        description = "Track /bin/login binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/login"

    strings:
        $s1 = "Can't open the faillog file (%s) to check UID %lu. User access authorized." ascii // found in 1/456 binaries
        $s2 = "No utmp entry.  You must exec \"login\" from the lowest level \"sh\"" ascii // found in 1/456 binaries
        $s3 = "unable to change owner or mode of tty stdin for user `%s': %s" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_loginctl_Binary {
    meta:
        description = "Track /bin/loginctl binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/loginctl"

    strings:
        $s1 = "  -o --output=STRING       Change journal output mode (short, short-precise," ascii // found in 1/456 binaries
        $s2 = "                             json, json-pretty, json-sse, json-seq, cat," ascii // found in 1/456 binaries
        $s3 = "  terminate-user USER...   Terminate all sessions of one or more users" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_logname_Binary {
    meta:
        description = "Track /bin/logname binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/logname"

    strings:
        $s1 = "82fbdf3cd8d8840792f33cfabdf9d6bd303304.debug" ascii // found in 1/456 binaries
        $s2 = "Print the user's login name." ascii // found in 1/456 binaries
        $s3 = "FIXME: unknown" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ls_Binary {
    meta:
        description = "Track /bin/ls binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ls"

    strings:
        $s1 = "ca7e3905b37d48cf0a88b576faa7b95cc3097b.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_lsattr_Binary {
    meta:
        description = "Track /bin/lsattr binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/lsattr"

    strings:
        $s1 = "Couldn't allocate path variable in lsattr_dir_proc" ascii // found in 1/456 binaries
        $s2 = "72f56e2d309c634c188933303aeeb476c4bcad.debug" ascii // found in 1/456 binaries
        $s3 = "Usage: %s [-RVadlpv] [files...]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_lsblk_Binary {
    meta:
        description = "Track /bin/lsblk binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/lsblk"

    strings:
        $s1 = " -y, --shell          use column names to be usable as shell variable identifiers" ascii // found in 1/456 binaries
        $s2 = " -M, --merge          group parents of sub-trees (usable for RAIDs, Multi-path)" ascii // found in 1/456 binaries
        $s3 = " -e, --exclude <list> exclude devices by major number (default: RAM disks)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_lscpu_Binary {
    meta:
        description = "Track /bin/lscpu binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/lscpu"

    strings:
        $s1 = "%s: options --all, --online and --offline may only be used with options --extended or --parse." ascii // found in 1/456 binaries
        $s2 = " -B, --bytes             print sizes in bytes rather than in human readable format" ascii // found in 1/456 binaries
        $s3 = " -a, --all               print both online and offline CPUs (default for -e)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_lsipc_Binary {
    meta:
        description = "Track /bin/lsipc binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/lsipc"

    strings:
        $s1 = " -b, --bytes              print SIZE in bytes rather than in human readable format" ascii // found in 1/456 binaries
        $s2 = " -g, --global      info about system-wide usage (may be used with -m, -q and -s)" ascii // found in 1/456 binaries
        $s3 = " -l, --list               force list output format (for example with --id)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_lslocks_Binary {
    meta:
        description = "Track /bin/lslocks binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/lslocks"

    strings:
        $s1 = " -b, --bytes            print SIZE in bytes rather than in human readable format" ascii // found in 1/456 binaries
        $s2 = " -p, --pid <pid>        display only locks held by this process" ascii // found in 1/456 binaries
        $s3 = " -i, --noinaccessible   ignore locks without read permissions" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_lslogins_Binary {
    meta:
        description = "Track /bin/lslogins binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/lslogins"

    strings:
        $s1 = " -p, --pwd                display information related to login by password." ascii // found in 1/456 binaries
        $s2 = " -f, --failed             display data about the users' last failed logins" ascii // found in 1/456 binaries
        $s3 = " -c, --colon-separate     display data in a format similar to /etc/passwd" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_lsmem_Binary {
    meta:
        description = "Track /bin/lsmem binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/lsmem"

    strings:
        $s1 = "     --summary[=when] print summary information (never,always or only)" ascii // found in 1/456 binaries
        $s2 = "options --{raw,json,pairs} and --summary=only are mutually exclusive" ascii // found in 1/456 binaries
        $s3 = " -s, --sysroot <dir>  use the specified directory as system root" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_lsns_Binary {
    meta:
        description = "Track /bin/lsns binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/lsns"

    strings:
        $s1 = " -t, --type <name>      namespace type (mnt, net, ipc, user, pid, uts, cgroup, time)" ascii // found in 1/456 binaries
        $s2 = " -T, --tree <rel>       use tree format (parent, owner, or process)" ascii // found in 1/456 binaries
        $s3 = " -W, --nowrap           don't use multi-line representation" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_lzmainfo_Binary {
    meta:
        description = "Track /bin/lzmainfo binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/lzmainfo"

    strings:
        $s1 = "Dictionary size:               %u MB (2^%u bytes)" ascii // found in 1/456 binaries
        $s2 = "Show information stored in the .lzma file header" ascii // found in 1/456 binaries
        $s3 = "2ea5ea9a319cb7a615546d08ec087d92f1e690.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_m4_Binary {
    meta:
        description = "Track /bin/m4 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/m4"

    strings:
        $s1 = "                                 (default stderr, discard if empty string)" ascii // found in 1/456 binaries
        $s2 = "Mandatory or optional arguments to long options are mandatory or optional" ascii // found in 1/456 binaries
        $s3 = "  -L, --nesting-limit=NUMBER   change nesting limit, 0 for unlimited [%d]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_make_Binary {
    meta:
        description = "Track /bin/make binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/make"

    strings:
        $s1 = "target-specific order-only second-expansion else-if shortest-stem undefine oneshell nocomment groupe" ascii // found in 1/456 binaries
        $s2 = ".out .a .ln .o .c .cc .C .cpp .p .f .F .m .r .y .l .ym .yl .s .S .mod .sym .def .h .info .dvi .tex ." ascii // found in 1/456 binaries
        $s3 = "%sLicense GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_makeconv_Binary {
    meta:
        description = "Track /bin/makeconv binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/makeconv"

    strings:
        $s1 = "makeconv version %u.%u, ICU tool to read .ucm codepage mapping files and write .cnv files" ascii // found in 1/456 binaries
        $s2 = "       the substitution character byte sequence is illegal in this codepage structure!" ascii // found in 1/456 binaries
        $s3 = "internal error: byte sequence reached reserved action code, entry 0x%02x: 0x%s (U+%x)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_mawk_Binary {
    meta:
        description = "Track /bin/mawk binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/mawk"

    strings:
        $s1 = "NOOPPPQRQSQTQUVQWWXXYYZZZZZZZZZ[[\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\]\\^\\_`\\aabbbbbbbbbbbbbbbbbbbcddeefgZhhiiijjkklZmZnZo" ascii // found in 1/456 binaries
        $s2 = " \"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"" ascii // found in 1/456 binaries
        $s3 = "    If no -f option is given, a \"--\" ends option processing; the following" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_mcookie_Binary {
    meta:
        description = "Track /bin/mcookie binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/mcookie"

    strings:
        $s1 = " -m, --max-size <num>  limit how much is read from seed files" ascii // found in 1/456 binaries
        $s2 = " -v, --verbose         explain what is being done" ascii // found in 1/456 binaries
        $s3 = " -f, --file <file>     use file as a cookie seed" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_md5sum_Binary {
    meta:
        description = "Track /bin/md5sum binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/md5sum"

    strings:
        $s1 = "c3bca9e5fb63f1188a797607a74a872dbecd9d.debug" ascii // found in 1/456 binaries
        $s2 = "RFC 1321" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_mdig_Binary {
    meta:
        description = "Track /bin/mdig binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/mdig"

    strings:
        $s1 = "(dns_requestmgr_create( mctx, taskmgr, dispatchmgr, have_ipv4 ? dispatchvx : ((void *)0), have_ipv6 " ascii // found in 1/456 binaries
        $s2 = "(dns_dispatch_createudp( dispatchmgr, have_src ? &srcaddr : &bind_any, &dispatchvx)) == ISC_R_SUCCES" ascii // found in 1/456 binaries
        $s3 = "                 +[no]crypto         (Control display of cryptographic fields in records)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_mesg_Binary {
    meta:
        description = "Track /bin/mesg binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/mesg"

    strings:
        $s1 = "Control write access of other users to your terminal." ascii // found in 1/456 binaries
        $s2 = "ttyname() failed, attempting to go around using: %s" ascii // found in 1/456 binaries
        $s3 = "6b0cfad9213e0bf50ec5f8feae7e70dadae379.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_mise_Binary {
    meta:
        description = "Track /bin/mise binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/mise"

    strings:
        $s1 = "rirunning shirt with sash dziwKutabireru fallen leaf bkhyrarcrossed swords children crossing tlhigha" ascii // found in 1/456 binaries
        $s2 = "usrsourcekitgpg not found, skipping verification--trust-modelalwaysubiamazonlinuxPassword manager de" ascii // found in 1/456 binaries
        $s3 = "valid section namerepositoryformatversionignorecaseprecomposeunicodeby now the `dot_git` dir is vali" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_mispipe_Binary {
    meta:
        description = "Track /bin/mispipe binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/mispipe"

    strings:
        $s1 = "Failed (in child) closing standard output  (while cleaning up)" ascii // found in 1/456 binaries
        $s2 = "Failed closing standard output (while cleaning up)" ascii // found in 1/456 binaries
        $s3 = "b2353c36e3c4e621728e5dc9f27c88adf5ba91.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_mkdir_Binary {
    meta:
        description = "Track /bin/mkdir binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/mkdir"

    strings:
        $s1 = "  -Z                   set SELinux security context of each created directory" ascii // found in 1/456 binaries
        $s2 = "  -p, --parents     no error if existing, make parent directories as needed," ascii // found in 1/456 binaries
        $s3 = "                    with their file modes unaffected by any -m option." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_mkfifo_Binary {
    meta:
        description = "Track /bin/mkfifo binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/mkfifo"

    strings:
        $s1 = "Create named pipes (FIFOs) with the given NAMEs." ascii // found in 1/456 binaries
        $s2 = "2f5ff803bae411d2ea3ec8fcd8acf75f410cbb.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_mknod_Binary {
    meta:
        description = "Track /bin/mknod binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/mknod"

    strings:
        $s1 = "it is interpreted as hexadecimal; otherwise, if it begins with 0, as octal;" ascii // found in 1/456 binaries
        $s2 = "Both MAJOR and MINOR must be specified when TYPE is b, c, or u, and they" ascii // found in 1/456 binaries
        $s3 = "must be omitted when TYPE is p.  If MAJOR or MINOR begins with 0x or 0X," ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_mktemp_Binary {
    meta:
        description = "Track /bin/mktemp binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/mktemp"

    strings:
        $s1 = "      --suffix=SUFF   append SUFF to TEMPLATE; SUFF must not contain a slash." ascii // found in 1/456 binaries
        $s2 = "                        This option is implied if TEMPLATE does not end in X" ascii // found in 1/456 binaries
        $s3 = "  -p DIR, --tmpdir[=DIR]  interpret TEMPLATE relative to DIR; if DIR is not" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_more_Binary {
    meta:
        description = "Track /bin/more binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/more"

    strings:
        $s1 = "Most commands optionally preceded by integer argument k.  Defaults in brackets." ascii // found in 1/456 binaries
        $s2 = "z                       Display next k lines of text [current screen size]*" ascii // found in 1/456 binaries
        $s3 = "d or ctrl-D             Scroll k lines [current scroll size, initially 11]*" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_mount_Binary {
    meta:
        description = "Track /bin/mount binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/mount"

    strings:
        $s1 = "       applications will generate AVC messages and not be allowed access to" ascii // found in 1/456 binaries
        $s2 = "       this file system.  For more details see restorecon(8) and mount(8)." ascii // found in 1/456 binaries
        $s3 = "       dmesg(1) may have more information after failed mount system call." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_mountpoint_Binary {
    meta:
        description = "Track /bin/mountpoint binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/mountpoint"

    strings:
        $s1 = " -x, --devno        print maj:min device number of the block device" ascii // found in 1/456 binaries
        $s2 = " -d, --fs-devno     print maj:min device number of the filesystem" ascii // found in 1/456 binaries
        $s3 = " -q, --quiet        quiet mode - don't print anything" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_msgattrib_Binary {
    meta:
        description = "Track /bin/msgattrib binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/msgattrib"

    strings:
        $s1 = "Filters the messages of a translation catalog according to their attributes," ascii // found in 1/456 binaries
        $s2 = "      --translated            keep translated, remove untranslated messages" ascii // found in 1/456 binaries
        $s3 = "      --untranslated          keep untranslated, remove translated messages" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_msgcat_Binary {
    meta:
        description = "Track /bin/msgcat binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/msgcat"

    strings:
        $s1 = "that if --use-first is specified, they will be taken from the first PO file" ascii // found in 1/456 binaries
        $s2 = "comments, extracted comments, and file positions will be cumulated, except" ascii // found in 1/456 binaries
        $s3 = "                              definitions, defaults to 0 if not set" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_msgcmp_Binary {
    meta:
        description = "Track /bin/msgcmp binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/msgcmp"

    strings:
        $s1 = "translations.  The ref.pot file is the last created PO file, or a PO Template" ascii // found in 1/456 binaries
        $s2 = "match cannot be found, fuzzy matching is used to produce better diagnostics." ascii // found in 1/456 binaries
        $s3 = "you have translated each and every message in your program.  Where an exact" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_msgcomm_Binary {
    meta:
        description = "Track /bin/msgcomm binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/msgcomm"

    strings:
        $s1 = "comments and extracted comments will be preserved, but only from the first" ascii // found in 1/456 binaries
        $s2 = "                              definitions, defaults to 1 if not set" ascii // found in 1/456 binaries
        $s3 = "PO file to define them.  File positions from all PO files will be" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_msgconv_Binary {
    meta:
        description = "Track /bin/msgconv binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/msgconv"

    strings:
        $s1 = "Converts a translation catalog to a different character encoding." ascii // found in 1/456 binaries
        $s2 = "The default encoding is the current locale's encoding." ascii // found in 1/456 binaries
        $s3 = "ce38751a6da0d54d5ccf2c6c009cc8983b88de.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_msgen_Binary {
    meta:
        description = "Track /bin/msgen binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/msgen"

    strings:
        $s1 = "created English PO file, or a PO Template file (generally created by" ascii // found in 1/456 binaries
        $s2 = "Creates an English translation catalog.  The input file is the last" ascii // found in 1/456 binaries
        $s3 = "xgettext).  Untranslated entries are assigned a translation that is" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_msgexec_Binary {
    meta:
        description = "Track /bin/msgexec binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/msgexec"

    strings:
        $s1 = "A special builtin command called '0' outputs the translation, followed by a" ascii // found in 1/456 binaries
        $s2 = "null byte.  The output of \"msgexec 0\" is suitable as input for \"xargs -0\"." ascii // found in 1/456 binaries
        $s3 = "The COMMAND can be any program that reads a translation from standard" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_msgfilter_Binary {
    meta:
        description = "Track /bin/msgfilter binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/msgfilter"

    strings:
        $s1 = "  -f, --file=SCRIPTFILE       add the contents of SCRIPTFILE to the commands" ascii // found in 1/456 binaries
        $s2 = "      --keep-header           keep header entry unmodified, don't filter it" ascii // found in 1/456 binaries
        $s3 = "The FILTER can be any program that reads a translation from standard input" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_msgfmt_Binary {
    meta:
        description = "Track /bin/msgfmt binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/msgfmt"

    strings:
        $s1 = "  public java.lang.Object handleGetObject (java.lang.String msgid) throws java.util.MissingResourceE" ascii // found in 1/456 binaries
        $s2 = "    return (value instanceof java.lang.String[] ? ((java.lang.String[])value)[0] : value);" ascii // found in 1/456 binaries
        $s3 = "      --csharp-resources      C# resources mode: generate a .NET .resources file" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_msggrep_Binary {
    meta:
        description = "Track /bin/msggrep binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/msggrep"

    strings:
        $s1 = "option '%c' cannot be used before 'J' or 'K' or 'T' or 'C' or 'X' has been specified" ascii // found in 1/456 binaries
        $s2 = "or if -X is given and the extracted comment matches EXTRACTED-COMMENT-PATTERN." ascii // found in 1/456 binaries
        $s3 = "or if -K is given and its key (msgid or msgid_plural) matches MSGID-PATTERN," ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_msginit_Binary {
    meta:
        description = "Track /bin/msginit binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/msginit"

    strings:
        $s1 = "https://www.gnu.org/software/gettext/manual/html_node/Setting-the-POSIX-Locale.html" ascii // found in 1/456 binaries
        $s2 = "If no input file is given, the current directory is searched for the POT file." ascii // found in 1/456 binaries
        $s3 = "Creates a new PO file, initializing the meta information with values from the" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_msgmerge_Binary {
    meta:
        description = "Track /bin/msgmerge binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/msgmerge"

    strings:
        $s1 = "Project-Id-VersiReport-Msgid-BugPOT-Creation-DatPO-Revision-DateLast-Translator:Content-Transfernsfe" ascii // found in 1/456 binaries
        $s2 = "%sRead %ld old + %ld reference, merged %ld, fuzzied %ld, missing %ld, obsolete %ld." ascii // found in 1/456 binaries
        $s3 = "The backup suffix is '~', unless set with --suffix or the SIMPLE_BACKUP_SUFFIX" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_msgunfmt_Binary {
    meta:
        description = "Track /bin/msgunfmt binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/msgunfmt"

    strings:
        $s1 = "file \"%s\" is not in GNU .mo format: Some messages are at a wrong index in the hash table." ascii // found in 1/456 binaries
        $s2 = "file \"%s\" is not in GNU .mo format: Some messages are not present in the hash table." ascii // found in 1/456 binaries
        $s3 = "      --csharp-resources      C# resources mode: input is a .NET .resources file" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_msguniq_Binary {
    meta:
        description = "Track /bin/msguniq binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/msguniq"

    strings:
        $s1 = "will be cumulated.  When using the --unique option, duplicates are discarded." ascii // found in 1/456 binaries
        $s2 = "  -u, --unique                print only unique messages, discard duplicates" ascii // found in 1/456 binaries
        $s3 = "default, duplicates are merged together.  When using the --repeated option," ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_mv_Binary {
    meta:
        description = "Track /bin/mv binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/mv"

    strings:
        $s1 = "If you specify more than one of -i, -f, -n, only the final one takes effect." ascii // found in 1/456 binaries
        $s2 = "  -t, --target-directory=DIRECTORY  move all SOURCE arguments into DIRECTORY" ascii // found in 1/456 binaries
        $s3 = "  -Z, --context                set SELinux security context of destination" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_namei_Binary {
    meta:
        description = "Track /bin/namei binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/namei"

    strings:
        $s1 = " -Z, --context       print any security context of each file " ascii // found in 1/456 binaries
        $s2 = " -x, --mountpoints   show mount point directories with a 'D'" ascii // found in 1/456 binaries
        $s3 = " -o, --owners        show owner and group name of each file" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_nasm_Binary {
    meta:
        description = "Track /bin/nasm binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/nasm"

    strings:
        $s1 = "times (%$pad / __?ALIGN_%[__?BITS?__]BIT_GROUP?__) db __?ALIGN_%[__?BITS?__]BIT_%[__?ALIGN_%[__?BITS" ascii // found in 1/456 binaries
        $s2 = "unable to find valid values for all labels after %ld passes; stalled for %ld, giving up." ascii // found in 1/456 binaries
        $s3 = "dropping trailing empty default parameter in definition of multi-line macro `%s'" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_nc_openbsd_Binary {
    meta:
        description = "Track /bin/nc.openbsd binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/nc.openbsd"

    strings:
        $s1 = "  [-q seconds] [-s sourceaddr] [-T keyword] [-V rtable] [-W recvlimit]" ascii // found in 1/456 binaries
        $s2 = "usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]" ascii // found in 1/456 binaries
        $s3 = "  [-m minttl] [-O length] [-P proxy_username] [-p source_port]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ndisasm_Binary {
    meta:
        description = "Track /bin/ndisasm binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ndisasm"

    strings:
        $s1 = "   -p selects the preferred vendor instruction set (intel, amd, cyrix, idt)" ascii // found in 1/456 binaries
        $s2 = "usage: ndisasm [-a] [-i] [-h] [-r] [-u] [-b bits] [-o origin] [-s sync...]" ascii // found in 1/456 binaries
        $s3 = "   -k avoids disassembling <bytes> bytes from position <start>" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_networkctl_Binary {
    meta:
        description = "Track /bin/networkctl binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/networkctl"

    strings:
        $s1 = "systemd-networkd.service not running in a network namespace (?), skipping netns check." ascii // found in 1/456 binaries
        $s2 = "networkctl must be invoked in same network namespace as systemd-networkd.service." ascii // found in 1/456 binaries
        $s3 = "  forcerenew DEVICES...  Trigger DHCP reconfiguration of all connected clients" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_newgrp_Binary {
    meta:
        description = "Track /bin/newgrp binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/newgrp"

    strings:
        $s1 = "Failed to crypt password with previous salt of group '%s'" ascii // found in 1/456 binaries
        $s2 = "user '%s' (login '%s' on %s) returned to group '%lu'" ascii // found in 1/456 binaries
        $s3 = "user '%s' (login '%s' on %s) switched to group '%s'" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ngettext_Binary {
    meta:
        description = "Track /bin/ngettext binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ngettext"

    strings:
        $s1 = "  MSGID MSGID-PLURAL        translate MSGID (singular) / MSGID-PLURAL (plural)" ascii // found in 1/456 binaries
        $s2 = "  COUNT                     choose singular/plural form based on this value" ascii // found in 1/456 binaries
        $s3 = "Display native language translation of a textual message whose grammatical" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_nice_Binary {
    meta:
        description = "Track /bin/nice binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/nice"

    strings:
        $s1 = "%d (most favorable to the process) to %d (least favorable to the process)." ascii // found in 1/456 binaries
        $s2 = "Run COMMAND with an adjusted niceness, which affects process scheduling." ascii // found in 1/456 binaries
        $s3 = "With no COMMAND, print the current niceness.  Niceness values range from" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ninja_Binary {
    meta:
        description = "Track /bin/ninja binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ninja"

    strings:
        $s1 = "There might be build flakiness if any of the targets listed above are built alone, or not late enoug" ascii // found in 1/456 binaries
        $s2 = "ninja executable version (%s) greater than build file ninja_required_version (%s); versions may be i" ascii // found in 1/456 binaries
        $s3 = "multiple rules generate %s. builds involving this target will not be correct; continuing anyway" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_nl_Binary {
    meta:
        description = "Track /bin/nl binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/nl"

    strings:
        $s1 = "  -l, --join-blank-lines=NUMBER   group of NUMBER empty lines counted as one" ascii // found in 1/456 binaries
        $s2 = "  -p, --no-renumber               do not reset line numbers for each section" ascii // found in 1/456 binaries
        $s3 = "a missing second character implies ':'.  As a GNU extension one can specify" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_nohup_Binary {
    meta:
        description = "Track /bin/nohup binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/nohup"

    strings:
        $s1 = "If standard output is a terminal, append output to 'nohup.out' if possible," ascii // found in 1/456 binaries
        $s2 = "If standard input is a terminal, redirect it from an unreadable file." ascii // found in 1/456 binaries
        $s3 = "If standard error is a terminal, redirect it to standard output." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_nproc_Binary {
    meta:
        description = "Track /bin/nproc binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/nproc"

    strings:
        $s1 = "Print the number of processing units available to the current process," ascii // found in 1/456 binaries
        $s2 = "      --all      print the number of installed processors" ascii // found in 1/456 binaries
        $s3 = "      --ignore=N  if possible, exclude N processing units" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_nsenter_Binary {
    meta:
        description = "Track /bin/nsenter binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/nsenter"

    strings:
        $s1 = " -e, --env              inherit environment variables from target process" ascii // found in 1/456 binaries
        $s2 = " -Z, --follow-context   set SELinux context according to --target PID" ascii // found in 1/456 binaries
        $s3 = " -W, --wdns <dir>       set the working directory in namespace" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_nslookup_Binary {
    meta:
        description = "Track /bin/nslookup binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/nslookup"

    strings:
        $s1 = "   nslookup [-opt ...] host        # just look up 'host' using default server" ascii // found in 1/456 binaries
        $s2 = "   nslookup [-opt ...]             # interactive mode using default server" ascii // found in 1/456 binaries
        $s3 = "   nslookup [-opt ...] host server # just look up 'host' using 'server'" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_nsupdate_Binary {
    meta:
        description = "Track /bin/nsupdate binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/nsupdate"

    strings:
        $s1 = "usage: nsupdate [-CdDi] [-L level] [-l] [-g | -o | -y keyname:secret | -k keyfile] [-p port] [-v] [-" ascii // found in 1/456 binaries
        $s2 = "class CLASS               (set the zone's DNS class, e.g. IN (default), CH)" ascii // found in 1/456 binaries
        $s3 = "oldgsstsig                (use Microsoft's GSS_TSIG to sign the request)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_numfmt_Binary {
    meta:
        description = "Track /bin/numfmt binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/numfmt"

    strings:
        $s1 = "Reformat NUMBER(s), or the numbers from standard input if none are specified." ascii // found in 1/456 binaries
        $s2 = "      --field=FIELDS   replace the numbers in these input fields (default=1);" ascii // found in 1/456 binaries
        $s3 = "      --from-unit=N    specify the input unit size (instead of the default 1)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_od_Binary {
    meta:
        description = "Track /bin/od binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/od"

    strings:
        $s1 = "  or:  %s --traditional [OPTION]... [FILE] [[+]OFFSET[.][b] [+][LABEL][.][b]]" ascii // found in 1/456 binaries
        $s2 = "      --endian={big|little}   swap input bytes according the specified order" ascii // found in 1/456 binaries
        $s3 = "  -A, --address-radix=RADIX   output format for file offsets; RADIX is one" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_openssl_Binary {
    meta:
        description = "Track /bin/openssl binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/openssl"

    strings:
        $s1 = "assertion failed: (family == AF_UNSPEC || family == BIO_ADDRINFO_family(res)) && (type == 0 || type " ascii // found in 1/456 binaries
        $s2 = "assertion failed: (family == AF_UNSPEC || family == BIO_ADDRINFO_family(ai)) && (type == 0 || type =" ascii // found in 1/456 binaries
        $s3 = "assertion failed: OSSL_NELEM(cmp_vars) == n_options + OPT_PROV__FIRST + 1 - OPT_PROV__LAST + OPT_R__" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_parallel_Binary {
    meta:
        description = "Track /bin/parallel binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/parallel"

    strings:
        $s1 = "for each argument, run command with argument, in parallel" ascii // found in 1/456 binaries
        $s2 = "44a637bd2d2a614c33fe23b14c68be06d8c7bb.debug" ascii // found in 1/456 binaries
        $s3 = "option -n cannot be used without a command" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_partx_Binary {
    meta:
        description = "Track /bin/partx binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/partx"

    strings:
        $s1 = " -n, --nr <n:m>       specify the range of partitions (e.g. --nr 2:4)" ascii // found in 1/456 binaries
        $s2 = " -d, --delete         delete specified partitions or all of them" ascii // found in 1/456 binaries
        $s3 = " -u, --update         update specified partitions or all of them" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_passwd_Binary {
    meta:
        description = "Track /bin/passwd binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/passwd"

    strings:
        $s1 = "You should set a password with usermod -p to unlock the password of this account." ascii // found in 1/456 binaries
        $s2 = "  -e, --expire                  force expire the password for the named account" ascii // found in 1/456 binaries
        $s3 = "  -S, --status                  report password status on the named account" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_paste_Binary {
    meta:
        description = "Track /bin/paste binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/paste"

    strings:
        $s1 = "  -s, --serial            paste one file at a time instead of in parallel" ascii // found in 1/456 binaries
        $s2 = "  -d, --delimiters=LIST   reuse characters from LIST instead of TABs" ascii // found in 1/456 binaries
        $s3 = "Write lines consisting of the sequentially corresponding lines from" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_patch_Binary {
    meta:
        description = "Track /bin/patch binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/patch"

    strings:
        $s1 = "((pch_char (old) == ' ' && pch_char (new) == ' ') || (pch_char (old) == '=' && pch_char (new) == '^'" ascii // found in 1/456 binaries
        $s2 = "can't do dry run on nonexistent version-controlled file %s; invoke '%s' and try again" ascii // found in 1/456 binaries
        $s3 = "  -Y PREFIX  --basename-prefix=PREFIX  Prepend PREFIX to backup file basenames." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pathchk_Binary {
    meta:
        description = "Track /bin/pathchk binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pathchk"

    strings:
        $s1 = "      --portability   check for all POSIX systems (equivalent to -p -P)" ascii // found in 1/456 binaries
        $s2 = "/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" ascii // found in 1/456 binaries
        $s3 = "  -P                  check for empty names and leading \"-\"" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pee_Binary {
    meta:
        description = "Track /bin/pee binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pee"

    strings:
        $s1 = "b5b27859a91abec2633c185f106c5804cf6249.debug" ascii // found in 1/456 binaries
        $s2 = "Can not open pipe to '%s'" ascii // found in 1/456 binaries
        $s3 = "--no-ignore-write-errors" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_perl_Binary {
    meta:
        description = "Track /bin/perl binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/perl"

    strings:
        $s1 = "l&cwlocrpcmadlmaghbahexahomarmiavstbatkbhksbuhdcakmcanschamchrscpmncprtcwucyrldsrtgonggrekgujrguruhl" ascii // found in 2/456 binaries
        $s2 = " HAS_TIMES MULTIPLICITY PERLIO_LAYERS PERL_HASH_FUNC_SIPHASH13 PERL_HASH_USE_SBOX32 USE_64_BIT_ALL U" ascii // found in 2/456 binaries
        $s3 = " HAS_LONG_DOUBLE HAS_STRTOLD PERL_COPY_ON_WRITE PERL_DONT_CREATE_GVSV PERL_MALLOC_WRAP PERL_OP_PAREN" ascii // found in 2/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_perl5_38_x86_64_linux_gnu_Binary {
    meta:
        description = "Track /bin/perl5.38-x86_64-linux-gnu binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/perl5.38-x86_64-linux-gnu"

    strings:
        $s1 = "/usr/lib/debug/.dwz/x86_64-linux-gnu/libperl5.38t64.debug" ascii // found in 1/456 binaries
        $s2 = "927e9a9933cfac683a97fba26381bae073828f.debug" ascii // found in 1/456 binaries
        $s3 = "libperl.so.5.38" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_perl5_38_2_Binary {
    meta:
        description = "Track /bin/perl5.38.2 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/perl5.38.2"

    strings:
        $s1 = "l&cwlocrpcmadlmaghbahexahomarmiavstbatkbhksbuhdcakmcanschamchrscpmncprtcwucyrldsrtgonggrekgujrguruhl" ascii // found in 2/456 binaries
        $s2 = " HAS_TIMES MULTIPLICITY PERLIO_LAYERS PERL_HASH_FUNC_SIPHASH13 PERL_HASH_USE_SBOX32 USE_64_BIT_ALL U" ascii // found in 2/456 binaries
        $s3 = " HAS_LONG_DOUBLE HAS_STRTOLD PERL_COPY_ON_WRITE PERL_DONT_CREATE_GVSV PERL_MALLOC_WRAP PERL_OP_PAREN" ascii // found in 2/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pgrep_Binary {
    meta:
        description = "Track /bin/pgrep binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pgrep"

    strings:
        $s1 = "pattern that searches for process name longer than 15 characters will result in zero matches" ascii // found in 2/456 binaries
        $s2 = "                           Available namespaces: ipc, mnt, net, pid, user, uts" ascii // found in 2/456 binaries
        $s3 = " -P, --parent <PPID,...>   match only child processes of the given parent" ascii // found in 2/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pidwait_Binary {
    meta:
        description = "Track /bin/pidwait binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pidwait"

    strings:
        $s1 = "pattern that searches for process name longer than 15 characters will result in zero matches" ascii // found in 2/456 binaries
        $s2 = "                           Available namespaces: ipc, mnt, net, pid, user, uts" ascii // found in 2/456 binaries
        $s3 = " -P, --parent <PPID,...>   match only child processes of the given parent" ascii // found in 2/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pinentry_curses_Binary {
    meta:
        description = "Track /bin/pinentry-curses binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pinentry-curses"

    strings:
        $s1 = "License GPLv2+: GNU GPL version 2 or later <https://www.gnu.org/licenses/>" ascii // found in 1/456 binaries
        $s2 = "along with this software.  If not, see <https://www.gnu.org/licenses/>." ascii // found in 1/456 binaries
        $s3 = "the Free Software Foundation; either version 2 of the License, or" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ping_Binary {
    meta:
        description = "Track /bin/ping binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ping"

    strings:
        $s1 = "Warning: IPv6 link-local address on ICMP datagram socket may require ifname or scope-id => use: addr" ascii // found in 1/456 binaries
        $s2 = "minimal interval for broadcast ping for user must be >= %d ms, use -i %s (or higher)" ascii // found in 1/456 binaries
        $s3 = "minimal interval for multicast ping for user must be >= %d ms, use -i %s (or higher)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pinky_Binary {
    meta:
        description = "Track /bin/pinky binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pinky"

    strings:
        $s1 = "  -i              omit the user's full name and remote host in short format" ascii // found in 1/456 binaries
        $s2 = "  -b              omit the user's home directory and shell in long format" ascii // found in 1/456 binaries
        $s3 = "  -q              omit the user's full name, remote host and idle time" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pkaction_Binary {
    meta:
        description = "Track /bin/pkaction binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pkaction"

    strings:
        $s1 = "polkit_action_description_get_implicit_inactive" ascii // found in 1/456 binaries
        $s2 = "polkit_action_description_get_implicit_active" ascii // found in 1/456 binaries
        $s3 = "polkit_action_description_get_annotation_keys" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pkcheck_Binary {
    meta:
        description = "Track /bin/pkcheck binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pkcheck"

    strings:
        $s1 = "  --revoke-temp                      Revoke all temporary authorizations for current session" ascii // found in 1/456 binaries
        $s2 = "  --enable-internal-agent            Use an internal authentication agent if necessary" ascii // found in 1/456 binaries
        $s3 = "  --list-temp                        List temporary authorizations for current session" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pkgconf_Binary {
    meta:
        description = "Track /bin/pkgconf binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pkgconf"

    strings:
        $s1 = "/lib:/lib/i386-linux-gnu:/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnux32:/lib32:/libx32:/usr/lib:/usr" ascii // found in 1/456 binaries
        $s2 = "  --define-prefix                   override the prefix variable with one that is guessed based on" ascii // found in 1/456 binaries
        $s3 = "  --personality=triplet|filename    sets the personality to 'triplet' or a file named 'filename'" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pkgdata_Binary {
    meta:
        description = "Track /bin/pkgdata binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pkgdata"

    strings:
        $s1 = "%s: Unable to locate pkgdata.inc. Unable to parse the results of '%s'. Check paths or use the -O opt" ascii // found in 1/456 binaries
        $s2 = "pkgdata: Error: absolute path encountered. Old style paths are not supported. Use relative paths suc" ascii // found in 1/456 binaries
        $s3 = "Warning: Providing a revision number with the -r option is recommended when packaging data in the cu" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pkttyagent_Binary {
    meta:
        description = "Track /bin/pkttyagent binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pkttyagent"

    strings:
        $s1 = "Authorization not available. Check if polkit service is running or see debug message for more inform" ascii // found in 1/456 binaries
        $s2 = "polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (subject)) == pid_of_caller" ascii // found in 1/456 binaries
        $s3 = "polkit_unix_process_get_start_time (POLKIT_UNIX_PROCESS (subject)) > 0" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pldd_Binary {
    meta:
        description = "Track /bin/pldd binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pldd"

    strings:
        $s1 = "List dynamic shared objects loaded into process." ascii // found in 1/456 binaries
        $s2 = "Exactly one parameter with process ID required." ascii // found in 1/456 binaries
        $s3 = "eb20767e35af40a033c013c3bb5263afd229c3.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pmap_Binary {
    meta:
        description = "Track /bin/pmap binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pmap"

    strings:
        $s1 = "# to show paths in the mapping column uncomment the following line" ascii // found in 1/456 binaries
        $s2 = "%20[0-9a-f]-%20[0-9a-f] %31s %20[0-9a-f] %63[0-9a-f:] %20s %127[^" ascii // found in 1/456 binaries
        $s3 = "            WARNING: format changes according to /proc/PID/smaps" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pr_Binary {
    meta:
        description = "Track /bin/pr binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pr"

    strings:
        $s1 = "                    use a centered HEADER instead of filename in page header," ascii // found in 1/456 binaries
        $s2 = "  -J, --join-lines  merge full lines, turns off -W line truncation, no column" ascii // found in 1/456 binaries
        $s3 = "                    multiple text-column output only, -s[char] turns off (72)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_printenv_Binary {
    meta:
        description = "Track /bin/printenv binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/printenv"

    strings:
        $s1 = "If no VARIABLE is specified, print name and value pairs for them all." ascii // found in 1/456 binaries
        $s2 = "  -0, --null     end each output line with NUL, not newline" ascii // found in 1/456 binaries
        $s3 = "Print the values of the specified environment VARIABLE(s)." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_printf_Binary {
    meta:
        description = "Track /bin/printf binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/printf"

    strings:
        $s1 = "          escaping non-printable characters with the proposed POSIX $'' syntax." ascii // found in 1/456 binaries
        $s2 = "  %q      ARGUMENT is printed in a format that can be reused as shell input," ascii // found in 1/456 binaries
        $s3 = "  \\uHHHH  Unicode (ISO/IEC 10646) character with hex value HHHH (4 digits)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_prlimit_Binary {
    meta:
        description = "Track /bin/prlimit binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/prlimit"

    strings:
        $s1 = " -f, --fsize            maximum size of files written by the process" ascii // found in 1/456 binaries
        $s2 = " -y, --rttime           CPU time in microseconds a process scheduled" ascii // found in 1/456 binaries
        $s3 = " <limit> is defined as a range soft:hard, soft:, :hard or a value to" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_protoc_Binary {
    meta:
        description = "Track /bin/protoc binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/protoc"

    strings:
        $s1 = "_ZN6google8protobuf8compiler20CommandLineInterface17RegisterGeneratorERKNSt7__cxx1112basic_stringIcS" ascii // found in 1/456 binaries
        $s2 = "_ZN6google8protobuf8compiler20CommandLineInterface17RegisterGeneratorERKNSt7__cxx1112basic_stringIcS" ascii // found in 1/456 binaries
        $s3 = "_ZN6google8protobuf8compiler20CommandLineInterface12AllowPluginsERKNSt7__cxx1112basic_stringIcSt11ch" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ps_Binary {
    meta:
        description = "Track /bin/ps binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ps"

    strings:
        $s1 = "Z...............................|||||||||||||||||||||||||||||||.????????????????                CGJK" ascii // found in 1/456 binaries
        $s2 = "pid,tname,majflt,minflt,m_trs,m_drs,m_size,m_swap,rss,m_share,vm_lib,m_dt,args" ascii // found in 1/456 binaries
        $s3 = "flags,state,user,pid,ppid,cpu,intpri,nice,addr,sz,wchan,stime,tty,time,args" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ptx_Binary {
    meta:
        description = "Track /bin/ptx binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ptx"

    strings:
        $s1 = "Output a permuted index, including context, of the words in the input files." ascii // found in 1/456 binaries
        $s2 = "  -w, --width=NUMBER             output width in columns, reference excluded" ascii // found in 1/456 binaries
        $s3 = "  -R, --right-side-refs          put references at right, not counted in -w" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pwd_Binary {
    meta:
        description = "Track /bin/pwd binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pwd"

    strings:
        $s1 = "  -L, --logical   use PWD from environment, even if it contains symlinks" ascii // found in 1/456 binaries
        $s2 = "Print the full filename of the current working directory." ascii // found in 1/456 binaries
        $s3 = "couldn't find directory entry in %s with matching i-node" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_pwdx_Binary {
    meta:
        description = "Track /bin/pwdx binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/pwdx"

    strings:
        $s1 = "844bc36ff4a27d27bfc1e8706d81f263c41a2a.debug" ascii // found in 1/456 binaries
        $s2 = "invalid process id: %s" ascii // found in 1/456 binaries
        $s3 = " %s [options] pid..." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_python3_12_Binary {
    meta:
        description = "Track /bin/python3.12 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/python3.12"

    strings:
        $s1 = "Bitwise inversion '~' on bool is deprecated. This returns the bitwise inversion of the underlying in" ascii // found in 1/456 binaries
        $s2 = "Guido van Rossum <guido@python.org>, Mike Verdone <mike.verdone@gmail.com>, Mark Russell <mark.russe" ascii // found in 1/456 binaries
        $s3 = "Python runtime initialized with LC_CTYPE=C (a locale with default ASCII encoding), which may cause U" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_re2c_Binary {
    meta:
        description = "Track /bin/re2c binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/re2c"

    strings:
        $s1 = ".;KZY962a24a1e67e418ca1c69a1f5ea2901b049b02.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_re2go_Binary {
    meta:
        description = "Track /bin/re2go binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/re2go"

    strings:
        $s1 = ".;KZY7ea3c7582b4166c4a7a6acc31a327fb8d57dfe.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_re2rust_Binary {
    meta:
        description = "Track /bin/re2rust binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/re2rust"

    strings:
        $s1 = ".;KZYaa4185c69af947a110f3f0579265518d0f8028.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_readlink_Binary {
    meta:
        description = "Track /bin/readlink binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/readlink"

    strings:
        $s1 = "                                every component of the given name recursively;" ascii // found in 1/456 binaries
        $s2 = "                                without requirements on components existence" ascii // found in 1/456 binaries
        $s3 = "  -s, --silent                  suppress most error messages (on by default)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_realpath_Binary {
    meta:
        description = "Track /bin/realpath binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/realpath"

    strings:
        $s1 = "  -m, --canonicalize-missing   no path components need exist or be a directory" ascii // found in 1/456 binaries
        $s2 = "      --relative-base=DIR      print absolute paths unless paths below DIR" ascii // found in 1/456 binaries
        $s3 = "  -z, --zero                   end each output line with NUL, not newline" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_recode_sr_latin_Binary {
    meta:
        description = "Track /bin/recode-sr-latin binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/recode-sr-latin"

    strings:
        $s1 = "The input text is read from standard input.  The converted text is output to" ascii // found in 1/456 binaries
        $s2 = "error while converting from \"%s\" encoding to \"%s\" encoding" ascii // found in 1/456 binaries
        $s3 = "Recode Serbian text from Cyrillic to Latin script." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_rename_ul_Binary {
    meta:
        description = "Track /bin/rename.ul binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/rename.ul"

    strings:
        $s1 = " -l, --last          replace only the last occurrence" ascii // found in 1/456 binaries
        $s2 = " -o, --no-overwrite  don't overwrite existing files" ascii // found in 1/456 binaries
        $s3 = " %s [options] <expression> <replacement> <file>..." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_renice_Binary {
    meta:
        description = "Track /bin/renice binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/renice"

    strings:
        $s1 = "                          If POSIXLY_CORRECT flag is set in environment" ascii // found in 1/456 binaries
        $s2 = "                          process priority. Otherwise it is 'absolute'." ascii // found in 1/456 binaries
        $s3 = "                          then the priority is 'relative' to current" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_resizepart_Binary {
    meta:
        description = "Track /bin/resizepart binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/resizepart"

    strings:
        $s1 = "Tell the kernel about the new size of a partition." ascii // found in 1/456 binaries
        $s2 = "%s: failed to get start of the partition number %s" ascii // found in 1/456 binaries
        $s3 = " %s <disk device> <partition number> <length>" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_rev_Binary {
    meta:
        description = "Track /bin/rev binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/rev"

    strings:
        $s1 = "709123db6bf21e13f7e2f87763cb083b1a3c80.debug" ascii // found in 1/456 binaries
        $s2 = "Usage: %s [options] [file ...]" ascii // found in 1/456 binaries
        $s3 = "Reverse lines characterwise." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_rg_Binary {
    meta:
        description = "Track /bin/rg binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/rg"

    strings:
        $s1 = "attempt to calculate the remainder with a divisor of zeroa Display implementation returned an error " ascii // found in 1/456 binaries
        $s2 = "}{/usr/share/cargo/registry/grep-matcher-0.1.7/src/interpolate.rsvalid UTF-8 capture name/usr/share/" ascii // found in 1/456 binaries
        $s3 = "grep_searcher::searcher/usr/share/cargo/registry/grep-searcher-0.1.13/src/searcher/mod.rsslice reade" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_rm_Binary {
    meta:
        description = "Track /bin/rm binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/rm"

    strings:
        $s1 = "  -I                    prompt once before removing more than three files, or" ascii // found in 1/456 binaries
        $s2 = "                          while still giving protection against most mistakes" ascii // found in 1/456 binaries
        $s3 = "assurance that the contents are truly unrecoverable, consider using shred(1)." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_rmdir_Binary {
    meta:
        description = "Track /bin/rmdir binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/rmdir"

    strings:
        $s1 = "                    ignore each failure to remove a non-empty directory" ascii // found in 1/456 binaries
        $s2 = "  -v, --verbose     output a diagnostic for every directory processed" ascii // found in 1/456 binaries
        $s3 = "                    e.g., 'rmdir -p a/b' is similar to 'rmdir a/b a'" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_rpcgen_Binary {
    meta:
        description = "Track /bin/rpcgen binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/rpcgen"

    strings:
        $s1 = "%s [-abkCLNTM][-Dname[=value]] [-i size] [-I [-K seconds]] [-Y path] infile" ascii // found in 1/456 binaries
        $s2 = " $(RM) core $(TARGETS) $(OBJECTS_CLNT) $(OBJECTS_SVC) $(CLIENT) $(SERVER)" ascii // found in 1/456 binaries
        $s3 = "voids allowed only inside union and program definitions with one argument" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_rsync_Binary {
    meta:
        description = "Track /bin/rsync binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/rsync"

    strings:
        $s1 = "*.3g2 *.3gp *.7z *.aac *.ace *.apk *.avi *.bz2 *.deb *.dmg *.ear *.f4v *.flac *.flv *.gpg *.gz *.iso" ascii // found in 1/456 binaries
        $s2 = "RCS SCCS CVS CVS.adm RCSLOG cvslog.* tags TAGS .make.state .nse_depinfo *~ #* .#* ,* _$* *$ *.old *." ascii // found in 1/456 binaries
        $s3 = "You can only specify --usermap o--groupmap conflicts with prior cify --groupmap --secluded-args conf" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_run_parts_Binary {
    meta:
        description = "Track /bin/run-parts binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/run-parts"

    strings:
        $s1 = "      --stdin         multiplex stdin to scripts being run, using temporary file" ascii // found in 1/456 binaries
        $s2 = "      --test          print script names which would run, but don't run them." ascii // found in 1/456 binaries
        $s3 = "      --regex=PATTERN validate filenames based on POSIX ERE pattern PATTERN." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_runcon_Binary {
    meta:
        description = "Track /bin/runcon binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/runcon"

    strings:
        $s1 = "  or:  %s [ -c ] [-u USER] [-r ROLE] [-t TYPE] [-l RANGE] COMMAND [args]" ascii // found in 1/456 binaries
        $s2 = "  -c, --compute      compute process transition context before modifying" ascii // found in 1/456 binaries
        $s3 = "With neither CONTEXT nor COMMAND, print the current security context." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_rustc_Binary {
    meta:
        description = "Track /bin/rustc binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/rustc"

    strings:
        $s1 = "de21e1c9c5c00bb321a7b395f6e50c59c79004.debug" ascii // found in 1/456 binaries
        $s2 = "_RNvCs4hW43al2D0k_17rustc_driver_impl4main" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_rustdoc_Binary {
    meta:
        description = "Track /bin/rustdoc binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/rustdoc"

    strings:
        $s1 = "called `Option::unwrap()` on a `None` valueASCIIAnyageASCII_Hex_DigitalphaAlphabeticalphabeticasciih" ascii // found in 1/456 binaries
        $s2 = "</html>src/librustdoc/html/render/context.rs../`  in crate ``. cratesource has no filename.html#-/<h" ascii // found in 1/456 binaries
        $s3 = "couldn't generate documentation: failed to create or modify \"starting to run rustcrun_global_ctxtfin" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_scalar_Binary {
    meta:
        description = "Track /bin/scalar binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/scalar"

    strings:
        $s1 = "scalar clone [--single-branch] [--branch <main-branch>] [--full-clone]" ascii // found in 1/456 binaries
        $s2 = "failed to get default branch name from remote; using local default" ascii // found in 1/456 binaries
        $s3 = "scalar [-C <directory>] [-c <key>=<value>] <command> [<options>]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_scp_Binary {
    meta:
        description = "Track /bin/scp binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/scp"

    strings:
        $s1 = "usage: scp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]" ascii // found in 1/456 binaries
        $s2 = "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]" ascii // found in 1/456 binaries
        $s3 = "server expand-path extension is required for ~user paths in SFTP mode" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_script_Binary {
    meta:
        description = "Track /bin/script binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/script"

    strings:
        $s1 = " -t[<file>], --timing[=<file>] deprecated alias to -T (default file is stderr)" ascii // found in 1/456 binaries
        $s2 = " -E, --echo <when>             echo input in session (auto, always or never)" ascii // found in 1/456 binaries
        $s3 = " -c, --command <command>       run command rather than interactive shell" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_scriptlive_Binary {
    meta:
        description = "Track /bin/scriptlive binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/scriptlive"

    strings:
        $s1 = " -c, --command <command> run command rather than interactive shell" ascii // found in 1/456 binaries
        $s2 = ">>> scriptlive: Starting your typescript execution by %s." ascii // found in 1/456 binaries
        $s3 = "02aefb5b428ee0599e7fcd040b41560c712726.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_scriptreplay_Binary {
    meta:
        description = "Track /bin/scriptreplay binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/scriptreplay"

    strings:
        $s1 = "     --summary           display overview about recorded session and exit" ascii // found in 1/456 binaries
        $s2 = " -x, --stream <name>     stream type (out, in, signal or info)" ascii // found in 1/456 binaries
        $s3 = " -c, --cr-mode <type>    CR char mode (auto, never, always)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sdiff_Binary {
    meta:
        description = "Track /bin/sdiff binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sdiff"

    strings:
        $s1 = "    --tabsize=NUM            tab stops at every NUM (default 8) print columns" ascii // found in 1/456 binaries
        $s2 = "-H, --speed-large-files      assume large files, many scattered small changes" ascii // found in 1/456 binaries
        $s3 = "-w, --width=NUM              output at most NUM (default 130) print columns" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sed_Binary {
    meta:
        description = "Track /bin/sed binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sed"

    strings:
        $s1 = "                 add the contents of script-file to the commands to be executed" ascii // found in 1/456 binaries
        $s2 = "                 load minimal amounts of data from the input files and flush" ascii // found in 1/456 binaries
        $s3 = "                 specify the desired line-wrap length for the `l' command" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_seq_Binary {
    meta:
        description = "Track /bin/seq binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/seq"

    strings:
        $s1 = "  -w, --equal-width        equalize width by padding with leading zeroes" ascii // found in 1/456 binaries
        $s2 = "it defaults to %.PRECf if FIRST, INCREMENT, and LAST are all fixed point" ascii // found in 1/456 binaries
        $s3 = "  -s, --separator=STRING   use STRING to separate numbers (default: \\n)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_setarch_Binary {
    meta:
        description = "Track /bin/setarch binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/setarch"

    strings:
        $s1 = " -R, --addr-no-randomize  disables randomization of the virtual address space" ascii // found in 1/456 binaries
        $s2 = " -3, --3gb                limits the used address space to a maximum of 3 GB" ascii // found in 1/456 binaries
        $s3 = "     --show[=personality] show current or specific personality and exit" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_setpriv_Binary {
    meta:
        description = "Track /bin/setpriv binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/setpriv"

    strings:
        $s1 = "uid %ld not found, --init-groups requires an user that can be found on the system" ascii // found in 1/456 binaries
        $s2 = "--[re]gid requires --keep-groups, --clear-groups, --init-groups, or --groups" ascii // found in 1/456 binaries
        $s3 = " --groups <group,...>        set supplementary groups by UID or name" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_setsid_Binary {
    meta:
        description = "Track /bin/setsid binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/setsid"

    strings:
        $s1 = " -c, --ctty     set the controlling terminal to the current one" ascii // found in 1/456 binaries
        $s2 = " -w, --wait     wait program to exit, and use the same return" ascii // found in 1/456 binaries
        $s3 = "b6d85535d392fa450eb6fb5eeefb0e9ef7015b.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_setterm_Binary {
    meta:
        description = "Track /bin/setterm binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/setterm"

    strings:
        $s1 = " --initialize                  display init string, and use default settings" ascii // found in 1/456 binaries
        $s2 = " --blank[=0-60|force|poke]     set time of inactivity before screen blanks" ascii // found in 1/456 binaries
        $s3 = " --linewrap on|off             continue on a new line when a line is full" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sftp_Binary {
    meta:
        description = "Track /bin/sftp binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sftp"

    strings:
        $s1 = "chmod [-h] mode path               Change permissions of file 'path' to 'mode'" ascii // found in 1/456 binaries
        $s2 = "df [-hi] [path]                    Display statistics for current directory or" ascii // found in 1/456 binaries
        $s3 = "chgrp [-h] grp path                Change group of file 'path' to 'grp'" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sha1sum_Binary {
    meta:
        description = "Track /bin/sha1sum binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sha1sum"

    strings:
        $s1 = "92fa4239350076ae4dde4eb1ae0b3426511072.debug" ascii // found in 1/456 binaries
        $s2 = "FIPS-180-1" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sha224sum_Binary {
    meta:
        description = "Track /bin/sha224sum binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sha224sum"

    strings:
        $s1 = "2f8bb896afc6d6f7d2f9743ad50b304a9da0bd.debug" ascii // found in 1/456 binaries
        $s2 = "RFC 3874" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sha256sum_Binary {
    meta:
        description = "Track /bin/sha256sum binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sha256sum"

    strings:
        $s1 = "6cd43c18a2466b69b78e2ef24c2fe72da3f133.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sha384sum_Binary {
    meta:
        description = "Track /bin/sha384sum binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sha384sum"

    strings:
        $s1 = "370fb8ffacdc7d3ca8308ea90dbc7ae6e1bd12.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sha512sum_Binary {
    meta:
        description = "Track /bin/sha512sum binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sha512sum"

    strings:
        $s1 = "d80e77548af78b29de62bbff214a30a1771cdb.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_shred_Binary {
    meta:
        description = "Track /bin/shred binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/shred"

    strings:
        $s1 = "CAUTION: shred assumes the file system and hardware overwrite data in place." ascii // found in 1/456 binaries
        $s2 = "      --remove[=HOW]  like -u but give control on HOW to delete;  See below" ascii // found in 1/456 binaries
        $s3 = "Delete FILE(s) if --remove (-u) is specified.  The default is not to remove" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_shuf_Binary {
    meta:
        description = "Track /bin/shuf binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/shuf"

    strings:
        $s1 = "  -i, --input-range=LO-HI   treat each number LO through HI as an input line" ascii // found in 1/456 binaries
        $s2 = "Write a random permutation of the input lines to standard output." ascii // found in 1/456 binaries
        $s3 = "  -e, --echo                treat each ARG as an input line" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_skill_Binary {
    meta:
        description = "Track /bin/skill binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/skill"

    strings:
        $s1 = " -n, --no-action    do not actually kill processes; just print what would happen" ascii // found in 1/456 binaries
        $s2 = " --nslist <ns,...>        list which namespaces will be considered for" ascii // found in 1/456 binaries
        $s3 = "Particularly useful signals include HUP, INT, KILL, STOP, CONT, and 0." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_slabtop_Binary {
    meta:
        description = "Track /bin/slabtop binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/slabtop"

    strings:
        $s1 = " -s, --sort <char>   specify sort criteria by character (see below)" ascii // found in 1/456 binaries
        $s2 = "  OBJS ACTIVE  USE OBJ SIZE  SLABS OBJ/SLAB CACHE SIZE NAME" ascii // found in 1/456 binaries
        $s3 = " -o, --once          only display once, then exit" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sleep_Binary {
    meta:
        description = "Track /bin/sleep binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sleep"

    strings:
        $s1 = "Pause for NUMBER seconds.  SUFFIX may be 's' for seconds (the default)," ascii // found in 1/456 binaries
        $s2 = "'m' for minutes, 'h' for hours or 'd' for days.  NUMBER need not be an" ascii // found in 1/456 binaries
        $s3 = "integer.  Given two or more arguments, pause for the amount of time" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sort_Binary {
    meta:
        description = "Track /bin/sort binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sort"

    strings:
        $s1 = "                                general-numeric -g, human-numeric -h, month -M," ascii // found in 1/456 binaries
        $s2 = "                              without -c, output only the first of an equal run" ascii // found in 1/456 binaries
        $s3 = "% 1% of memory, b 1, K 1024 (default), and so on for M, G, T, P, E, Z, Y, R, Q." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_split_Binary {
    meta:
        description = "Track /bin/split binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/split"

    strings:
        $s1 = "      --numeric-suffixes[=FROM]  same as -d, but allow setting the start value" ascii // found in 1/456 binaries
        $s2 = "  -n, --number=CHUNKS     generate CHUNKS output files; see explanation below" ascii // found in 1/456 binaries
        $s3 = "  -t, --separator=SEP     use SEP instead of newline as the record separator;" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sponge_Binary {
    meta:
        description = "Track /bin/sponge binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sponge"

    strings:
        $s1 = "sponge [-a] <file>: soak up all input from stdin and write it to <file>" ascii // found in 1/456 binaries
        $s2 = "9fc3f841f1061473c6ee537378c02faa705daf.debug" ascii // found in 1/456 binaries
        $s3 = "error writing buffer to temporary file" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sqlite3_Binary {
    meta:
        description = "Track /bin/sqlite3 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sqlite3"

    strings:
        $s1 = "SELECT      'EXPLAIN QUERY PLAN SELECT 1 FROM ' || quote(s.name) || ' WHERE '  || group_concat(quote" ascii // found in 1/456 binaries
        $s2 = "WITH Lzn(nlz) AS (  SELECT 0 AS nlz  UNION  SELECT nlz+1 AS nlz FROM Lzn  WHERE EXISTS(   SELECT 1  " ascii // found in 1/456 binaries
        $s3 = "WITH trunk(pgno) AS (  SELECT read_i32(getpage(1), 8) AS x WHERE x>0    UNION  SELECT read_i32(getpa" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ssh_Binary {
    meta:
        description = "Track /bin/ssh binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ssh"

    strings:
        $s1 = "ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v" ascii // found in 1/456 binaries
        $s2 = "gss-group14-sha256-,gss-group16-sha512-,gss-nistp256-sha256-,gss-curve25519-sha256-,gss-group14-sha1" ascii // found in 1/456 binaries
        $s3 = "CA/revocation marker, manual host list or wildcard host pattern found, skipping UserKnownHostsFile u" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ssh_add_Binary {
    meta:
        description = "Track /bin/ssh-add binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ssh-add"

    strings:
        $s1 = "Invalid key destination constraint \"%s\": does not specify user or host" ascii // found in 1/456 binaries
        $s2 = "usage: ssh-add [-cDdKkLlqvXx] [-E fingerprint_hash] [-H hostkey_file]" ascii // found in 1/456 binaries
        $s3 = "               [-h destination_constraint] [-S provider] [-t life]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ssh_agent_Binary {
    meta:
        description = "Track /bin/ssh-agent binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ssh-agent"

    strings:
        $s1 = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,s" ascii // found in 1/456 binaries
        $s2 = "refusing use of destination-constrained key: mismatch between hostkey in request and most recently b" ascii // found in 1/456 binaries
        $s3 = "refusing use of destination-constrained key: no hostkey recorded in signature for forwarded connecti" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ssh_keygen_Binary {
    meta:
        description = "Track /bin/ssh-keygen binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ssh-keygen"

    strings:
        $s1 = "       ssh-keygen -Y match-principals -I signer_identity -f allowed_signers_file" ascii // found in 1/456 binaries
        $s2 = "       ssh-keygen -I certificate_identity -s ca_key [-hU] [-D pkcs11_provider]" ascii // found in 1/456 binaries
        $s3 = "       ssh-keygen -Y find-principals -s signature_file -f allowed_signers_file" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ssh_keyscan_Binary {
    meta:
        description = "Track /bin/ssh-keyscan binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ssh-keyscan"

    strings:
        $s1 = "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp52" ascii // found in 1/456 binaries
        $s2 = "rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com" ascii // found in 1/456 binaries
        $s3 = "usage: ssh-keyscan [-46cDHv] [-f file] [-O option] [-p port] [-T timeout]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_stat_Binary {
    meta:
        description = "Track /bin/stat binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/stat"

    strings:
        $s1 = "  %Hr  major device type in decimal, for character/block device special files" ascii // found in 1/456 binaries
        $s2 = "  %Lr  minor device type in decimal, for character/block device special files" ascii // found in 1/456 binaries
        $s3 = "  -f, --file-system     display file system status instead of file status" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_stdbuf_Binary {
    meta:
        description = "Track /bin/stdbuf binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/stdbuf"

    strings:
        $s1 = "In this case the corresponding stream will be fully buffered with the buffer" ascii // found in 1/456 binaries
        $s2 = "KB 1000, K 1024, MB 1000*1000, M 1024*1024, and so on for G,T,P,E,Z,Y,R,Q." ascii // found in 1/456 binaries
        $s3 = "NOTE: If COMMAND adjusts the buffering of its standard streams ('tee' does" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_stty_Binary {
    meta:
        description = "Track /bin/stty binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/stty"

    strings:
        $s1 = " * [-]drain      wait for transmission before applying settings (%s by default)" ascii // found in 1/456 binaries
        $s2 = " * size          print the number of rows and columns according to the kernel" ascii // found in 1/456 binaries
        $s3 = "   [-]parenb     generate parity bit in output and expect parity bit in input" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_su_Binary {
    meta:
        description = "Track /bin/su binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/su"

    strings:
        $s1 = "user %s does not exist or the user entry does not contain all the required fields" ascii // found in 1/456 binaries
        $s2 = " -c, --command <command>         pass a single command to the shell with -c" ascii // found in 1/456 binaries
        $s3 = " --session-command <command>     pass a single command to the shell with -c" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sudo_Binary {
    meta:
        description = "Track /bin/sudo binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sudo"

    strings:
        $s1 = "--build=x86_64-linux-gnu --prefix=/usr --includedir=${prefix}/include --mandir=${prefix}/share/man -" ascii // found in 1/456 binaries
        $s2 = "a terminal is required to read the password; either use the -S option to read from standard input or" ascii // found in 1/456 binaries
        $s3 = "effective uid is not %d, is %s on a file system with the 'nosuid' option set or an NFS file system w" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sudoreplay_Binary {
    meta:
        description = "Track /bin/sudoreplay binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sudoreplay"

    strings:
        $s1 = "  -l, --list             list available session IDs, with optional expression" ascii // found in 1/456 binaries
        $s2 = "  -n, --non-interactive  no prompts, session is sent to the standard output" ascii // found in 1/456 binaries
        $s3 = "  -m, --max-wait=num     max number of seconds to wait between events" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sum_Binary {
    meta:
        description = "Track /bin/sum binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sum"

    strings:
        $s1 = "  -r              use BSD sum algorithm (the default), use 1K blocks" ascii // found in 1/456 binaries
        $s2 = "  -s, --sysv      use System V sum algorithm, use 512 bytes blocks" ascii // found in 1/456 binaries
        $s3 = "c3dbea5e44c2a75fcb8ec88472cfd0ee086750.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_swig3_0_Binary {
    meta:
        description = "Track /bin/swig3.0 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/swig3.0"

    strings:
        $s1 = "    global::System.Reflection.MethodInfo methodInfo = this.GetType().GetMethod(methodName, global::S" ascii // found in 1/456 binaries
        $s2 = "The nspace feature is used on '%s' without -package. The generated code may not compile as Java does" ascii // found in 1/456 binaries
        $s3 = "SWIGINTERN const char *swig_readonly(ClientData clientData SWIGUNUSED, Tcl_Interp *interp SWIGUNUSED" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_sync_Binary {
    meta:
        description = "Track /bin/sync binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/sync"

    strings:
        $s1 = "  -f, --file-system      sync the file systems that contain the files" ascii // found in 1/456 binaries
        $s2 = "  -d, --data             sync only file data, no unneeded metadata" ascii // found in 1/456 binaries
        $s3 = "If one or more files are specified, sync only them," ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemctl_Binary {
    meta:
        description = "Track /bin/systemctl binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemctl"

    strings:
        $s1 = "+PAM +AUDIT +SELINUX +APPARMOR +IMA +SMACK +SECCOMP +GCRYPT -GNUTLS +OPENSSL +ACL +BLKID +CURL +ELFU" ascii // found in 1/456 binaries
        $s2 = "Creating journal file %s on a btrfs file system, and copy-on-write is enabled. This is likely to slo" ascii // found in 1/456 binaries
        $s3 = "Creating journal file %s on a btrfs file system, and copy-on-write is enabled. This is likely to slo" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_ac_power_Binary {
    meta:
        description = "Track /bin/systemd-ac-power binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-ac-power"

    strings:
        $s1 = "     --low              Check if battery is discharging and low" ascii // found in 1/456 binaries
        $s2 = "Report whether we are connected to an external power source." ascii // found in 1/456 binaries
        $s3 = "Failed to read battery discharging + low status: %m" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_analyze_Binary {
    meta:
        description = "Track /bin/systemd-analyze binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-analyze"

    strings:
        $s1 = "Options --root= and --image= are only supported for cat-config, verify, condition and security when " ascii // found in 1/456 binaries
        $s2 = "# %sUnlisted System Calls%s (supported by the local kernel, but not included in any of the groups li" ascii // found in 1/456 binaries
        $s3 = "Hint: this expression is a valid calendar specification. Use 'systemd-analyze calendar \"%s\"' instead" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_ask_password_Binary {
    meta:
        description = "Track /bin/systemd-ask-password binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-ask-password"

    strings:
        $s1 = "     --keyname=NAME   Kernel key name for caching passwords (e.g. \"cryptsetup\")" ascii // found in 1/456 binaries
        $s2 = "                      Credential name for ImportCredential=, LoadCredential= or" ascii // found in 1/456 binaries
        $s3 = "  -n                  Do not suffix password written to standard output with" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_cat_Binary {
    meta:
        description = "Track /bin/systemd-cat binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-cat"

    strings:
        $s1 = "     --level-prefix=BOOL         Control whether level prefix shall be parsed" ascii // found in 1/456 binaries
        $s2 = "     --stderr-priority=PRIORITY  Set priority value (0..7) used for stderr" ascii // found in 1/456 binaries
        $s3 = "%sExecute process with stdout/stderr connected to the journal.%s" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_cgls_Binary {
    meta:
        description = "Track /bin/systemd-cgls binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-cgls"

    strings:
        $s1 = "  -u --unit           Show the subtrees of specified system units" ascii // found in 1/456 binaries
        $s2 = "     --user-unit      Show the subtrees of specified user units" ascii // found in 1/456 binaries
        $s3 = "  -a --all            Show all groups, including empty" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_cgtop_Binary {
    meta:
        description = "Track /bin/systemd-cgtop binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-cgtop"

    strings:
        $s1 = "<%1$sp%2$s> By path; <%1$st%2$s> By tasks/procs; <%1$sc%2$s> By CPU; <%1$sm%2$s> By memory; <%1$si%2" ascii // found in 1/456 binaries
        $s2 = "<%1$s+%2$s> Inc. delay; <%1$s-%2$s> Dec. delay; <%1$s%%%2$s> Toggle time; <%1$sSPACE%2$s> Refresh" ascii // found in 1/456 binaries
        $s3 = "Non-recursive counting is only supported when counting processes, not tasks. Use -P or -k." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_creds_Binary {
    meta:
        description = "Track /bin/systemd-creds binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-creds"

    strings:
        $s1 = "No credential name specified, not validating credential name embedded in encrypted data. (Disable th" ascii // found in 1/456 binaries
        $s2 = "No credential name specified, not embedding credential name in encrypted data. (Disable this warning" ascii // found in 1/456 binaries
        $s3 = "     --timestamp=TIME     Include specified timestamp in encrypted credential" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_cryptenroll_Binary {
    meta:
        description = "Track /bin/systemd-cryptenroll binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-cryptenroll"

    strings:
        $s1 = "When both enrolling and unlocking with FIDO2 tokens, automatic discovery is unsupported. Please spec" ascii // found in 1/456 binaries
        $s2 = "Token JSON data's keyslot filed is not an integer formatted as string, ignoring." ascii // found in 1/456 binaries
        $s3 = "                       Whether to require user verification to unlock the volume" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_cryptsetup_Binary {
    meta:
        description = "Track /bin/systemd-cryptsetup binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-cryptsetup"

    strings:
        $s1 = "Automatic PKCS#11 metadata discovery was not possible because missing or not unique, falling back to" ascii // found in 1/456 binaries
        $s2 = "Automatic FIDO2 metadata discovery was not possible because missing or not unique, falling back to t" ascii // found in 1/456 binaries
        $s3 = "No TPM2 metadata matching the current system state found in LUKS2 header, falling back to traditiona" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_delta_Binary {
    meta:
        description = "Track /bin/systemd-delta binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-delta"

    strings:
        $s1 = "  -t --type=LIST...   Only display a selected set of override types" ascii // found in 1/456 binaries
        $s2 = "     --diff[=1|0]     Show a diff when overridden files differ" ascii // found in 1/456 binaries
        $s3 = "737c001c5d3f82300dff84baa98dc0514c31e0.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_detect_virt_Binary {
    meta:
        description = "Track /bin/systemd-detect-virt binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-detect-virt"

    strings:
        $s1 = "     --private-users    Only detect whether we are running in a user namespace" ascii // found in 1/456 binaries
        $s2 = "     --list             List all known and detectable types of virtualization" ascii // found in 1/456 binaries
        $s3 = "     --list-cvm         List all known and detectable types of confidential " ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_escape_Binary {
    meta:
        description = "Track /bin/systemd-escape binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-escape"

    strings:
        $s1 = "Input '%s' is not an absolute file system path, escaping is likely not going to be reversible." ascii // found in 1/456 binaries
        $s2 = "Input '%s' is not a valid file system path, escaping is likely not going be reversible." ascii // found in 1/456 binaries
        $s3 = "  -p --path               When escaping/unescaping assume the string is a path" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_firstboot_Binary {
    meta:
        description = "Track /bin/systemd-firstboot binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-firstboot"

    strings:
        $s1 = "passwd: root account with non-shadow password found, treating root as configured" ascii // found in 1/456 binaries
        $s2 = "Only installed locale is default locale anyway, not setting locale explicitly." ascii // found in 1/456 binaries
        $s3 = "     --copy                       Copy locale, keymap, timezone, root password" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_id128_Binary {
    meta:
        description = "Track /bin/systemd-id128 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-id128"

    strings:
        $s1 = "Verb \"invocation-id\" cannot be combined with --app-specific=." ascii // found in 1/456 binaries
        $s2 = "  invocation-id           Print the ID of current invocation" ascii // found in 1/456 binaries
        $s3 = "  -p --pretty             Generate samples of program code" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_inhibit_Binary {
    meta:
        description = "Track /bin/systemd-inhibit binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-inhibit"

    strings:
        $s1 = "     --what=WHAT          Operations to inhibit, colon separated list of:" ascii // found in 1/456 binaries
        $s2 = "     --why=STRING         A descriptive string why is being inhibited" ascii // found in 1/456 binaries
        $s3 = "                          handle-suspend-key, handle-hibernate-key," ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_machine_id_setup_Binary {
    meta:
        description = "Track /bin/systemd-machine-id-setup binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-machine-id-setup"

    strings:
        $s1 = "%sInitialize /etc/machine-id from a random source.%s" ascii // found in 1/456 binaries
        $s2 = "     --print                Print used machine ID" ascii // found in 1/456 binaries
        $s3 = "../src/machine-id-setup/machine-id-setup-main.c" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_mount_Binary {
    meta:
        description = "Track /bin/systemd-mount binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-mount"

    strings:
        $s1 = "Can't find mount point of %s. It is expected that %s is already mounted on a place." ascii // found in 1/456 binaries
        $s2 = "  -G --collect                    Unload unit after it stopped, even when failed" ascii // found in 1/456 binaries
        $s3 = "     --fsck=no                    Don't run file system check before mount" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_notify_Binary {
    meta:
        description = "Track /bin/systemd-notify binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-notify"

    strings:
        $s1 = "     --ready           Inform the service manager about service start-up/reload" ascii // found in 1/456 binaries
        $s2 = "     --reloading       Inform the service manager about configuration reloading" ascii // found in 1/456 binaries
        $s3 = "Failed to determine whether we are booted with systemd, assuming we aren't: %m" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_path_Binary {
    meta:
        description = "Track /bin/systemd-path binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-path"

    strings:
        $s1 = "     --no-pager         Do not pipe output into a pager" ascii // found in 1/456 binaries
        $s2 = "     --suffix=SUFFIX    Suffix to append to paths" ascii // found in 1/456 binaries
        $s3 = "3b6c6f1c23851e37989a563343a31b528776c7.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_repart_Binary {
    meta:
        description = "Track /bin/systemd-repart binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-repart"

    strings:
        $s1 = "Partition %u:%u has non-matching partition type %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x" ascii // found in 1/456 binaries
        $s2 = "File system behind %s is reported by btrfs to be backed by pseudo-device /dev/root, which is not a v" ascii // found in 1/456 binaries
        $s3 = "Partition type %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x not supported from a" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_run_Binary {
    meta:
        description = "Track /bin/systemd-run binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-run"

    strings:
        $s1 = "Scope command line contains environment variable, which is not expanded by default for now, but will" ascii // found in 1/456 binaries
        $s2 = "Running as unit: %s; invocation ID: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x" ascii // found in 1/456 binaries
        $s3 = "--pty/--pipe is only supported when connecting to the local system or containers." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_socket_activate_Binary {
    meta:
        description = "Track /bin/systemd-socket-activate binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-socket-activate"

    strings:
        $s1 = "Datagram sockets do not accept connections. The --datagram and --accept options may not be combined." ascii // found in 1/456 binaries
        $s2 = "     --seqpacket             Listen on SOCK_SEQPACKET instead of stream socket" ascii // found in 1/456 binaries
        $s3 = "     --inetd                 Enable inetd file descriptor passing protocol" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_stdio_bridge_Binary {
    meta:
        description = "Track /bin/systemd-stdio-bridge binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-stdio-bridge"

    strings:
        $s1 = "  -p --bus-path=PATH     Path to the bus address (default: %s)" ascii // found in 1/456 binaries
        $s2 = "  -M --machine=CONTAINER Name of local container to connect to" ascii // found in 1/456 binaries
        $s3 = "Forward messages between a pipe or socket and a D-Bus bus." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_sysext_Binary {
    meta:
        description = "Track /bin/systemd-sysext binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-sysext"

    strings:
        $s1 = "Hierarchy '%s' reports a different device major/minor than what we are seeing, assuming offline copy" ascii // found in 1/456 binaries
        $s2 = "Failed to parse the extension metadata to know if the manager needs to be reloaded, ignoring: %m" ascii // found in 1/456 binaries
        $s3 = "     --noexec=BOOL        Whether to mount extension overlay with noexec" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_sysusers_Binary {
    meta:
        description = "Track /bin/systemd-sysusers binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-sysusers"

    strings:
        $s1 = "Requested user %s with UID %u and gid%u to be created is duplicated or conflicts with another user." ascii // found in 1/456 binaries
        $s2 = "Requested group %s with GID %u to be created is duplicated or conflicts with another user." ascii // found in 1/456 binaries
        $s3 = "Use either --root= or --image=, the combination of both is not supported." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_tmpfiles_Binary {
    meta:
        description = "Track /bin/systemd-tmpfiles binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-tmpfiles"

    strings:
        $s1 = "/proc/ is not mounted, but required for successful operation of systemd-tmpfiles. Please mount /proc" ascii // found in 1/456 binaries
        $s2 = "Cannot set file attributes for '%s', maybe due to incompatibility in specified attributes, previous=" ascii // found in 1/456 binaries
        $s3 = "Refusing to set permissions on hardlinked file %s while the fs.protected_hardlinks sysctl is turned " ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_systemd_tty_ask_password_agent_Binary {
    meta:
        description = "Track /bin/systemd-tty-ask-password-agent binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/systemd-tty-ask-password-agent"

    strings:
        $s1 = "     --console[=DEVICE]  Ask question on /dev/console (or DEVICE if specified)" ascii // found in 1/456 binaries
        $s2 = "     --wall              Continuously forward password requests to wall" ascii // found in 1/456 binaries
        $s3 = "     --plymouth          Ask question with Plymouth instead of on TTY" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_tabs_Binary {
    meta:
        description = "Track /bin/tabs binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/tabs"

    strings:
        $s1 = "A tabstop-list is an ordered list of column numbers, e.g., 1,11,21" ascii // found in 1/456 binaries
        $s2 = "  -d       debug (show ruler with expected/actual tab positions)" ascii // found in 1/456 binaries
        $s3 = "  -n       no-op (do not modify terminal settings)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_tac_Binary {
    meta:
        description = "Track /bin/tac binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/tac"

    strings:
        $s1 = "  -r, --regex              interpret the separator as a regular expression" ascii // found in 1/456 binaries
        $s2 = "  -s, --separator=STRING   use STRING as the separator instead of newline" ascii // found in 1/456 binaries
        $s3 = "  -b, --before             attach the separator before instead of after" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_tail_Binary {
    meta:
        description = "Track /bin/tail binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/tail"

    strings:
        $s1 = "  -n, --lines=[+]NUM       output the last NUM lines, instead of the last %d;" ascii // found in 1/456 binaries
        $s2 = "                             or use -n +NUM to skip NUM-1 lines at the start" ascii // found in 1/456 binaries
        $s3 = "                             (this is the usual case of rotated log files);" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_tar_Binary {
    meta:
        description = "Track /bin/tar binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/tar"

    strings:
        $s1 = "process only the NUMBERth occurrence of each file in the archive; this option is valid only in conju" ascii // found in 1/456 binaries
        $s2 = "print total bytes after processing the archive; with an argument - print total bytes when this SIGNA" ascii // found in 1/456 binaries
        $s3 = "preserve access times on dumped files, either by restoring the times after reading (METHOD='replace'" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_taskset_Binary {
    meta:
        description = "Track /bin/taskset binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/taskset"

    strings:
        $s1 = " -a, --all-tasks         operate on all the tasks (threads) for a given pid" ascii // found in 1/456 binaries
        $s2 = " -c, --cpu-list          display and specify cpus in list format" ascii // found in 1/456 binaries
        $s3 = "List format uses a comma-separated list instead of a mask:" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_tclsh8_6_Binary {
    meta:
        description = "Track /bin/tclsh8.6 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/tclsh8.6"

    strings:
        $s1 = "4da11d79984acad39412df8a09716eb75c71da.debug" ascii // found in 1/456 binaries
        $s2 = "Tcl_MainEx" ascii // found in 1/456 binaries
        $s3 = "~/.tclshrc" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_tee_Binary {
    meta:
        description = "Track /bin/tee binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/tee"

    strings:
        $s1 = "  -p                        operate in a more appropriate MODE with pipes." ascii // found in 1/456 binaries
        $s2 = "      --output-error[=MODE]   set behavior on write error.  See MODE below" ascii // found in 1/456 binaries
        $s3 = "With \"nopipe\" MODEs, exit immediately if all outputs become broken pipes." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_tempfile_Binary {
    meta:
        description = "Track /bin/tempfile binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/tempfile"

    strings:
        $s1 = "WARNING: tempfile is deprecated; consider using mktemp instead." ascii // found in 1/456 binaries
        $s2 = "-p, --prefix=STRING  set temporary file's prefix to STRING" ascii // found in 1/456 binaries
        $s3 = "-s, --suffix=STRING  set temporary file's suffix to STRING" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_test_Binary {
    meta:
        description = "Track /bin/test binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/test"

    strings:
        $s1 = "ea4266b3fc9e8a318364a69b54256a33f68f75.debug" ascii // found in 1/456 binaries
        $s2 = "coreutils" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_tic_Binary {
    meta:
        description = "Track /bin/tic binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/tic"

    strings:
        $s1 = "[-e names] [-o dir] [-R name] [-v[n]] [-V] [-w[n]] [-1aCDcfGgIKLNrsTtUx] source-file" ascii // found in 1/456 binaries
        $s2 = "  -D         print list of tic's database locations (first must be writable)" ascii // found in 1/456 binaries
        $s3 = "  -e<names>  translate/compile only entries named by comma-separated list" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_timedatectl_Binary {
    meta:
        description = "Track /bin/timedatectl binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/timedatectl"

    strings:
        $s1 = "%sWarning: The system is configured to read the RTC time in the local time zone." ascii // found in 1/456 binaries
        $s2 = "         time is never updated, it relies on external facilities to maintain it." ascii // found in 1/456 binaries
        $s3 = "         This mode cannot be fully supported. It will create various problems" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_timeout_Binary {
    meta:
        description = "Track /bin/timeout binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/timeout"

    strings:
        $s1 = "'s' for seconds (the default), 'm' for minutes, 'h' for hours or 'd' for days." ascii // found in 1/456 binaries
        $s2 = "It may be necessary to use the KILL signal, since this signal can't be caught." ascii // found in 1/456 binaries
        $s3 = "Upon timeout, send the TERM signal to COMMAND, if no other SIGNAL specified." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_tload_Binary {
    meta:
        description = "Track /bin/tload binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/tload"

    strings:
        $s1 = "Load average file /proc/loadavg does not exist" ascii // found in 1/456 binaries
        $s2 = " -d, --delay <secs>  update delay in seconds" ascii // found in 1/456 binaries
        $s3 = "cee489c3dd0a030fb9c64e4b5d932a425db053.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_toe_Binary {
    meta:
        description = "Track /bin/toe binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/toe"

    strings:
        $s1 = "e9c9accabecce3ca1adc5b8d6159facae11d4e.debug" ascii // found in 1/456 binaries
        $s2 = "%s: can't open terminfo directory %s" ascii // found in 1/456 binaries
        $s3 = "usage: %s [-ahsuUV] [-v n] [file...]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_top_Binary {
    meta:
        description = "Track /bin/top binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/top"

    strings:
        $s1 = "%s~3%#5.1f ~2us,~3%#5.1f ~2sy,~3%#5.1f ~2ni,~3%#5.1f ~2id,~3%#5.1f ~2wa,~3%#5.1f ~2hi,~3%#5.1f ~2si," ascii // found in 1/456 binaries
        $s2 = "winflags=%d, sortindx=%d, maxtasks=%d, graph_cpus=%d, graph_mems=%d, double_up=%d, combine_cpus=%d, " ascii // found in 1/456 binaries
        $s3 = "%s~3 %#5.1f ~2us,~3 %#5.1f ~2sy,~3 %#5.1f ~2ni,~3 %#5.1f ~2id,~3 %#5.1f ~2wa,~3 %#5.1f ~2hi,~3 %#5.1" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_touch_Binary {
    meta:
        description = "Track /bin/touch binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/touch"

    strings:
        $s1 = "  -h, --no-dereference   affect each symbolic link instead of any referenced" ascii // found in 1/456 binaries
        $s2 = "Update the access and modification times of each FILE to the current time." ascii // found in 1/456 binaries
        $s3 = "  -t STAMP               use [[CC]YY]MMDDhhmm[.ss] instead of current time" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_tput_Binary {
    meta:
        description = "Track /bin/tput binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/tput"

    strings:
        $s1 = "  capname     unlike clear/init/reset, print value for capability \"capname\"" ascii // found in 1/456 binaries
        $s2 = "  -S <<       read commands from standard input" ascii // found in 1/456 binaries
        $s3 = "9aeee07abd51330eb3dd93b6fc71c34b311f8f.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_tr_Binary {
    meta:
        description = "Track /bin/tr binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/tr"

    strings:
        $s1 = "ARRAYs are specified as strings of characters.  Most represent themselves." ascii // found in 1/456 binaries
        $s2 = "Translation occurs if -d is not given and both STRING1 and STRING2 appear." ascii // found in 1/456 binaries
        $s3 = "-t is only significant when translating.  ARRAY2 is extended to length of" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_true_Binary {
    meta:
        description = "Track /bin/true binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/true"

    strings:
        $s1 = "eac9874954214754c1c072a55bedc595b32c14.debug" ascii // found in 1/456 binaries
        $s2 = "Exit with a status code indicating success." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_truncate_Binary {
    meta:
        description = "Track /bin/truncate binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/truncate"

    strings:
        $s1 = "  -o, --io-blocks        treat SIZE as number of IO blocks instead of bytes" ascii // found in 1/456 binaries
        $s2 = "If a FILE is shorter, it is extended and the sparse extended part (hole)" ascii // found in 1/456 binaries
        $s3 = "SIZE may also be prefixed by one of the following modifying characters:" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_tset_Binary {
    meta:
        description = "Track /bin/tset binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/tset"

    strings:
        $s1 = "%s: can't initialize terminal type %s (error %d)" ascii // found in 1/456 binaries
        $s2 = "  -Q          do not output control key settings" ascii // found in 1/456 binaries
        $s3 = "The -S option is not supported under terminfo." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_tsort_Binary {
    meta:
        description = "Track /bin/tsort binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/tsort"

    strings:
        $s1 = "Write totally ordered list consistent with the partial ordering in FILE." ascii // found in 1/456 binaries
        $s2 = "a70082b4876342600dc8de62572622e5137c1f.debug" ascii // found in 1/456 binaries
        $s3 = "%s: input contains an odd number of tokens" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_tty_Binary {
    meta:
        description = "Track /bin/tty binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/tty"

    strings:
        $s1 = "  -s, --silent, --quiet   print nothing, only return an exit status" ascii // found in 1/456 binaries
        $s2 = "Print the file name of the terminal connected to standard input." ascii // found in 1/456 binaries
        $s3 = "05f1a910c8bc54ee9a3ad712ad92ff7e59e379.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_uclampset_Binary {
    meta:
        description = "Track /bin/uclampset binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/uclampset"

    strings:
        $s1 = "Utilization value range is [0:1024]. Use special -1 value to reset to system's default." ascii // found in 1/456 binaries
        $s2 = " %1$s [options] --pid <pid> | --system | <command> <arg>..." ascii // found in 1/456 binaries
        $s3 = "Show or change the utilization clamping attributes." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_uconv_Binary {
    meta:
        description = "Track /bin/uconv binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/uconv"

    strings:
        $s1 = "_ZN6icu_7414Transliterator15createFromRulesERKNS_13UnicodeStringES3_15UTransDirectionR11UParseErrorR" ascii // found in 1/456 binaries
        $s2 = "_ZN6icu_7414Transliterator14createInstanceERKNS_13UnicodeStringE15UTransDirectionR10UErrorCode" ascii // found in 1/456 binaries
        $s3 = "%s: warning, problem installing our static resource bundle data uconvmsg: %s - trying anyways." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_umount_Binary {
    meta:
        description = "Track /bin/umount binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/umount"

    strings:
        $s1 = "%s: failed to determine source (--all-targets is unsupported on systems with regular mtab file)." ascii // found in 1/456 binaries
        $s2 = " -f, --force             force unmount (in case of an unreachable NFS system)" ascii // found in 1/456 binaries
        $s3 = " -A, --all-targets       unmount all mountpoints for the given device in the" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_uname_Binary {
    meta:
        description = "Track /bin/uname binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/uname"

    strings:
        $s1 = "  -a, --all                print all information, in the following order," ascii // found in 1/456 binaries
        $s2 = "  -i, --hardware-platform  print the hardware platform (non-portable)" ascii // found in 1/456 binaries
        $s3 = "  -p, --processor          print the processor type (non-portable)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_unexpand_Binary {
    meta:
        description = "Track /bin/unexpand binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/unexpand"

    strings:
        $s1 = "      --first-only  convert only leading sequences of blanks (overrides -a)" ascii // found in 1/456 binaries
        $s2 = "  -t, --tabs=N     have tabs N characters apart instead of 8 (enables -a)" ascii // found in 1/456 binaries
        $s3 = "  -a, --all        convert all blanks, instead of just initial blanks" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_uniq_Binary {
    meta:
        description = "Track /bin/uniq binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/uniq"

    strings:
        $s1 = "      --group[=METHOD]  show all items, separating groups with an empty line;" ascii // found in 1/456 binaries
        $s2 = "                                 METHOD={none(default),prepend,separate}" ascii // found in 1/456 binaries
        $s3 = "                          METHOD={separate(default),prepend,append,both}" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_unlink_Binary {
    meta:
        description = "Track /bin/unlink binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/unlink"

    strings:
        $s1 = "Call the unlink function to remove the specified FILE." ascii // found in 1/456 binaries
        $s2 = "05f593088558c908e907a09c2e5ddc1f66c51e.debug" ascii // found in 1/456 binaries
        $s3 = "Usage: %s FILE" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_unshare_Binary {
    meta:
        description = "Track /bin/unshare binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/unshare"

    strings:
        $s1 = "                           map count groups from outergid to innergid (implies --user)" ascii // found in 1/456 binaries
        $s2 = "                           map count users from outeruid to inneruid (implies --user)" ascii // found in 1/456 binaries
        $s3 = " --monotonic <offset>      set clock monotonic offset (seconds) in time namespaces" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_unzip_Binary {
    meta:
        description = "Track /bin/unzip binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/unzip"

    strings:
        $s1 = "         match directory separator /, but ** does.  Allows matching at specific" ascii // found in 2/456 binaries
        $s2 = "%s  -O CHARSET  specify a character encoding for DOS, Windows and OS/2 archives" ascii // found in 2/456 binaries
        $s3 = "  -I CHARSET  [UNIX] Specify a character encoding for UNIX and other archives." ascii // found in 2/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_unzipsfx_Binary {
    meta:
        description = "Track /bin/unzipsfx binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/unzipsfx"

    strings:
        $s1 = "Valid options are -tfupcz and -d <exdir>; modifiers are -abjnoqCL%sV%s." ascii // found in 1/456 binaries
        $s2 = "UnZipSFX %d.%d%d%s of %s, by Info-ZIP (http://www.info-zip.org)." ascii // found in 1/456 binaries
        $s3 = "  End-of-central-directory signature not found." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_update_alternatives_Binary {
    meta:
        description = "Track /bin/update-alternatives binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/update-alternatives"

    strings:
        $s1 = "alternative %s (part of link group %s) doesn't exist; removing from list of alternatives" ascii // found in 1/456 binaries
        $s2 = "%s%s/%s has been changed (manually or by a script); switching to manual updates only" ascii // found in 1/456 binaries
        $s3 = "skip creation of %s because associated file %s (of link group %s) doesn't exist" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_uptime_Binary {
    meta:
        description = "Track /bin/uptime binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/uptime"

    strings:
        $s1 = " -p, --pretty   show uptime in pretty format" ascii // found in 1/456 binaries
        $s2 = "56da05f956ee4931a67c49d80a949db6b96914.debug" ascii // found in 1/456 binaries
        $s3 = " -s, --since    system up since" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_users_Binary {
    meta:
        description = "Track /bin/users binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/users"

    strings:
        $s1 = "Output who is currently logged in according to FILE." ascii // found in 1/456 binaries
        $s2 = "a08840c9810d2c55a564d3d65a33fd6162b725.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_utmpdump_Binary {
    meta:
        description = "Track /bin/utmpdump binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/utmpdump"

    strings:
        $s1 = " -o, --output <file>  write to file instead of standard output" ascii // found in 1/456 binaries
        $s2 = "[%d] [%05d] [%-4.4s] [%-*.*s] [%-*.*s] [%-*.*s] [%-15s] [%s]" ascii // found in 1/456 binaries
        $s3 = " -f, --follow         output appended data as the file grows" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_varlinkctl_Binary {
    meta:
        description = "Track /bin/varlinkctl binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/varlinkctl"

    strings:
        $s1 = "Failed to parse returned interface description at %u:%u, showing raw interface description: %m" ascii // found in 1/456 binaries
        $s2 = "Unrecognized path '%s' is neither an AF_UNIX socket, nor an executable binary." ascii // found in 1/456 binaries
        $s3 = "  -j                     Same as --json=pretty on tty, --json=short otherwise" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_vdir_Binary {
    meta:
        description = "Track /bin/vdir binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/vdir"

    strings:
        $s1 = "fba364dfdc79b3f5998fc71f9db5c137a05e77.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_vmstat_Binary {
    meta:
        description = "Track /bin/vmstat binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/vmstat"

    strings:
        $s1 = "%2s %2s %6s %6s %6s %6s %4s %4s %5s %5s %4s %4s %2s %2s %2s %2s %4s %4s %12s %12s %12s %12s %4s %4s " ascii // found in 1/456 binaries
        $s2 = "--procs-- -----------------------memory---------------------- ---swap-- -----io---- -system-- ------" ascii // found in 1/456 binaries
        $s3 = "disk- -------------------reads------------------- -------------------writes------------------ ------" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_w_Binary {
    meta:
        description = "Track /bin/w binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/w"

    strings:
        $s1 = "User length environment PROCPS_USERLEN must be between 8 and %i, ignoring." ascii // found in 1/456 binaries
        $s2 = " -i, --ip-addr       display IP address instead of hostname (if possible)" ascii // found in 1/456 binaries
        $s3 = "from length environment PROCPS_FROMLEN must be between 8 and %d, ignoring" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_wall_Binary {
    meta:
        description = "Track /bin/wall binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/wall"

    strings:
        $s1 = " -n, --nobanner          do not print banner, works only for root" ascii // found in 1/456 binaries
        $s2 = " -g, --group <group>     only send message to group" ascii // found in 1/456 binaries
        $s3 = "getgrouplist found more groups than sysconf allows" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_watch_Binary {
    meta:
        description = "Track /bin/watch binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/watch"

    strings:
        $s1 = "  -C, --no-color         do not interpret ANSI color and style sequences" ascii // found in 1/456 binaries
        $s2 = "                         exit when output from command does not change" ascii // found in 1/456 binaries
        $s3 = "  -c, --color            interpret ANSI color and style sequences" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_watchgnupg_Binary {
    meta:
        description = "Track /bin/watchgnupg binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/watchgnupg"

    strings:
        $s1 = "License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>" ascii // found in 1/456 binaries
        $s2 = "  --tcp         listen on a TCP port and optionally on a local socket" ascii // found in 1/456 binaries
        $s3 = "  --time-only   print only the time; not a full timestamp" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_wc_Binary {
    meta:
        description = "Track /bin/wc binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/wc"

    strings:
        $s1 = "The options below may be used to select which counts are printed, always in" ascii // found in 1/456 binaries
        $s2 = "more than one FILE is specified.  A word is a non-zero-length sequence of" ascii // found in 1/456 binaries
        $s3 = "the following order: newline, word, character, byte, maximum line length." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_wdctl_Binary {
    meta:
        description = "Track /bin/wdctl binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/wdctl"

    strings:
        $s1 = " -I, --noident          don't print watchdog identity information" ascii // found in 1/456 binaries
        $s2 = " -x, --flags-only       print only flags table (same as -I -T)" ascii // found in 1/456 binaries
        $s3 = " -r, --raw              use raw output format for flags table" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_wget_Binary {
    meta:
        description = "Track /bin/wget binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/wget"

    strings:
        $s1 = "ABEDABELABETABLEABUTACHEACIDACMEACREACTAACTSADAMADDSADENAFARAFROAGEEAHEMAHOYAIDAAIDEAIDSAIRYAJARAKIN" ascii // found in 1/456 binaries
        $s2 = "gcc -DHAVE_CONFIG_H -DSYSTEM_WGETRC=\"/etc/wgetrc\" -DLOCALEDIR=\"/usr/share/locale\" -I. -I../../src -I" ascii // found in 1/456 binaries
        $s3 = "gcc -DHAVE_LIBSSL -DNDEBUG -g -O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -ffile-prefix" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_whereis_Binary {
    meta:
        description = "Track /bin/whereis binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/whereis"

    strings:
        $s1 = "Locate the binary, source, and manual-page files for a command." ascii // found in 1/456 binaries
        $s2 = " -g         interpret name as glob (pathnames pattern)" ascii // found in 1/456 binaries
        $s3 = " -m         search only for manuals and infos" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_who_Binary {
    meta:
        description = "Track /bin/who binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/who"

    strings:
        $s1 = "  -q, --count       all login names and number of users logged on" ascii // found in 1/456 binaries
        $s2 = "If ARG1 ARG2 given, -m presumed: 'am i' or 'mom likes' are usual." ascii // found in 1/456 binaries
        $s3 = "  -m                only hostname and user associated with stdin" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_whoami_Binary {
    meta:
        description = "Track /bin/whoami binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/whoami"

    strings:
        $s1 = "Print the user name associated with the current effective user ID." ascii // found in 1/456 binaries
        $s2 = "d3addb2acd364c843caad7b475324f60623425.debug" ascii // found in 1/456 binaries
        $s3 = "cannot find name for user ID %lu" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_wish8_6_Binary {
    meta:
        description = "Track /bin/wish8.6 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/wish8.6"

    strings:
        $s1 = "69324601671271daef001715bf70ff227cf63a.debug" ascii // found in 1/456 binaries
        $s2 = "Tcl_FindExecutable" ascii // found in 1/456 binaries
        $s3 = "Tcl_StaticPackage" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_addr2line_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-addr2line binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-addr2line"

    strings:
        $s1 = "  -R --recurse-limit     Enable a limit on recursion whilst demangling.  [Default]" ascii // found in 1/456 binaries
        $s2 = " If no addresses are specified on the command line, they will be read from stdin" ascii // found in 1/456 binaries
        $s3 = "  -j --section=<name>    Read section-relative offsets instead of addresses" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_ar_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-ar binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-ar"

    strings:
        $s1 = "Usage: %s [emulation options] [-]{dmpqrstx}[abcDfilMNoOPsSTuvV] [--plugin <name>] [member-name] [cou" ascii // found in 2/456 binaries
        $s2 = "  [u]          - only replace files that are newer than current archive contents" ascii // found in 2/456 binaries
        $s3 = "`u' is not meaningful with the `D' option - replacement will always happen." ascii // found in 2/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_as_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-as binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-as"

    strings:
        $s1 = "Infinite loop encountered whilst attempting to compute the addresses of symbols in section %s" ascii // found in 1/456 binaries
        $s2 = "  --gdwarf-sections       generate per-function section names for DWARF line information" ascii // found in 1/456 binaries
        $s3 = "                          what to do with multibyte characters encountered in the input" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_c__filt_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-c++filt binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-c++filt"

    strings:
        $s1 = "  [-R|--recurse-limit]        Enable a limit on recursion whilst demangling.  [Default]" ascii // found in 1/456 binaries
        $s2 = "  ]-r|--no-recurse-limit]     Disable a limit on recursion whilst demangling" ascii // found in 1/456 binaries
        $s3 = "  [-i|--no-verbose]           Do not show implementation details (if any)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_cpp_13_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-cpp-13 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-cpp-13"

    strings:
        $s1 = "%qs is not a valid option to the preprocessor" ascii // found in 1/456 binaries
        $s2 = "d0829cdfc9d35c9d4abc22c491981810908000.debug" ascii // found in 1/456 binaries
        $s3 = "too many input files" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_dwp_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-dwp binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-dwp"

    strings:
        $s1 = "Debug abbreviations extend beyond .debug_abbrev section; failed to reduce debug ug abbreviations" ascii // found in 1/456 binaries
        $s2 = "  -e EXE, --exec EXE       Get list of dwo files from EXE (defaults output to EXE.dwp)" ascii // found in 1/456 binaries
        $s3 = "%s: .dwp file must have no more than one .debug_types.dwo section" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_elfedit_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-elfedit binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-elfedit"

    strings:
        $s1 = "  -v --version                Display the version number of %s" ascii // found in 1/456 binaries
        $s2 = "  -h --help                   Display this information" ascii // found in 1/456 binaries
        $s3 = "                              Set output machine type" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_g___13_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-g++-13 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-g++-13"

    strings:
        $s1 = "0bbdcb90c9272a77ad9570ce32bb508ffbb239.debug" ascii // found in 1/456 binaries
        $s2 = "../../src/gcc/cp/g++spec.cc" ascii // found in 1/456 binaries
        $s3 = "lang_specific_driver" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_gcc_13_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-gcc-13 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-gcc-13"

    strings:
        $s1 = "14c7eee78e5a9399f369cea79657f21b73aead.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_gcc_ar_13_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-gcc-ar-13 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-gcc-ar-13"

    strings:
        $s1 = "3a094c68ac30c07ff91911288f8a8744550764.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_gcc_nm_13_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-gcc-nm-13 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-gcc-nm-13"

    strings:
        $s1 = "87dfaa0f04ebfa642763c885c65c7d1ab3b32f.debug" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_gcc_ranlib_13_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-gcc-ranlib-13 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-gcc-ranlib-13"

    strings:
        $s1 = "f62409c4182b6c6810c1c81da8eb97e0fd1a88.debug" ascii // found in 1/456 binaries
        $s2 = "gcc-ranlib" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_gcov_13_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-gcov-13 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-gcov-13"

    strings:
        $s1 = "/usr/lib/debug/.debug/.build-id/%s: __pos (which is %zu) > this->size() (which is %zu)" ascii // found in 1/456 binaries
        $s2 = "  -o, --object-directory DIR|FILE Search for object files in DIR or called FILE" ascii // found in 1/456 binaries
        $s3 = "  -q, --use-hotness-colors        Emit perf-like colored output for hot lines" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_gcov_dump_13_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-gcov-dump-13 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-gcov-dump-13"

    strings:
        $s1 = "  -s, --stable         Print content in stable format usable for comparison" ascii // found in 1/456 binaries
        $s2 = "  -r, --raw            Print content records in raw format" ascii // found in 1/456 binaries
        $s3 = "Copyright (C) 2023 Free Software Foundation, Inc." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_gcov_tool_13_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-gcov-tool-13 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-gcov-tool-13"

    strings:
        $s1 = "libgcov profiling error:%s:overwriting an existing profile data with a different checksum" ascii // found in 1/456 binaries
        $s2 = "    -h, --hotonly                       Only print info for hot objects/functions" ascii // found in 1/456 binaries
        $s3 = "libgcov profiling error:%s:Version mismatch - expected %s (%.4s) got %s (%.4s)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_gp_archive_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-gp-archive binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-gp-archive"

    strings:
        $s1 = " If you know the correct location of the missing file(s) you can help gp-archive to find them by man" ascii // found in 1/456 binaries
        $s2 = "Warning: Option -F is ignored because specified experiment name %s does not match founder experiment" ascii // found in 1/456 binaries
        $s3 = "Default archiving does not occur in case the application profiled terminates prematurely," ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_gp_collect_app_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-gp-collect-app binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-gp-collect-app"

    strings:
        $s1 = "                       of the tracing (on, off, <threshold>, or all); <API> is used to select the AP" ascii // found in 1/456 binaries
        $s2 = " -l <signal>       specify a signal that will trigger a sample of process-wide resource utilization." ascii // found in 1/456 binaries
        $s3 = " -s <option>[,<API>]  enable synchronization wait tracing; <option> is used to define the specifics" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_gp_display_src_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-gp-display-src binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-gp-display-src"

    strings:
        $s1 = "gprofng(1), gp-archive(1), gp-collect-app(1), gp-display-html(1), gp-display-text(1)" ascii // found in 1/456 binaries
        $s2 = "                         instructions; the same definitions for item and tag apply." ascii // found in 1/456 binaries
        $s3 = "Display the source code listing, or source code interleaved with disassembly code," ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_gp_display_text_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-gp-display-text binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-gp-display-text"

    strings:
        $s1 = "_ZN7DbeView13get_hist_dataEP10MetricListN8Histable4TypeEiN9Hist_data4ModeEP6VectorIPS2_ES7_S9_N8Path" ascii // found in 1/456 binaries
        $s2 = "  data_idx = %d lfilter = \"%s\" arg = \"%s\" func1 = \"%s\" aggr1 = \"%s\" func2 = \"%s\" aggr2 = \"%s\" func3 " ascii // found in 1/456 binaries
        $s3 = "  data_idx = %d lfilter = \"%s\" fexpr = \"%s\" time = \"%s\" tstart = %lld delta = %lld num = %d key = \"%" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_gprof_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-gprof binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-gprof"

    strings:
        $s1 = "[--demangle[=STYLE]] [--no-demangle] [--external-symbol-table=name] [@FILE]" ascii // found in 1/456 binaries
        $s2 = "Based on BSD gprof, copyright 1983 Regents of the University of California." ascii // found in 1/456 binaries
        $s3 = "%s: Only one of --function-ordering and --file-ordering may be specified." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_gprofng_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-gprofng binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-gprofng"

    strings:
        $s1 = "                                           the default is 256; set to 0 to disable capturing" ascii // found in 1/456 binaries
        $s2 = "gp-archive(1), gp-collect-app(1), gp-display-html(1), gp-display-src(1), gp-display-text(1)" ascii // found in 1/456 binaries
        $s3 = "                                    is 256; set to 0 to disable capturing of call stacks." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_ld_bfd_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-ld.bfd binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-ld.bfd"

    strings:
        $s1 = "%P: warning: auto-importing has been activated without --enable-auto-import specified on the command" ascii // found in 1/456 binaries
        $s2 = "%P:%pS: warning: --enable-non-contiguous-regions may change behaviour for section `%pA' from `%pB' (" ascii // found in 1/456 binaries
        $s3 = "%P: Relaxation not supported with --enable-non-contiguous-regions (section `%pA' would overflow `%pA" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_ld_gold_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-ld.gold binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-ld.gold"

    strings:
        $s1 = "unexpected reloc %u against global symbol %s without base register in object file when generating a " ascii // found in 1/456 binaries
        $s2 = "unexpected reloc %u against local symbol without base register in object file when generating a posi" ascii // found in 1/456 binaries
        $s3 = "Read_symbols groRead_symbols libDebug abbreviations extend beyond .debug_abbrev section; failed to r" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_lto_dump_13_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-lto-dump-13 binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-lto-dump-13"

    strings:
        $s1 = "DIVIDED BY HORIZONTAL BAR AND TOP HALF DIVIDED BY VERTICAL BARUIGHUR KIRGHIZ YEH WITH HAMZA ABOVE WI" ascii // found in 1/456 binaries
        $s2 = ", grp_read = %d, grp_write = %d, grp_assignment_read = %d, grp_assignment_write = %d, grp_scalar_rea" ascii // found in 1/456 binaries
        $s3 = "_ZN26complex_operations_pattern7matchesE18_complex_operationP8hash_mapIP9_slp_tree19_complex_perm_ki" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_nm_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-nm binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-nm"

    strings:
        $s1 = "Name                  Value           Class        Type         Size             Line  Section" ascii // found in 1/456 binaries
        $s2 = "      --without-symbol-versions  Do not display version strings after symbol names" ascii // found in 1/456 binaries
        $s3 = "                         Specify how to treat UTF-8 encoded unicode characters" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_objcopy_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-objcopy binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-objcopy"

    strings:
        $s1 = "local, global, export, debug, function, weak, section, constructor, warning, indirect, file, object," ascii // found in 2/456 binaries
        $s2 = "alloc, load, noload, readonly, debug, code, data, rom, exclude, contents, merge, strings, (COFF spec" ascii // found in 2/456 binaries
        $s3 = "                                   Produce deterministic output when stripping archives (default)" ascii // found in 2/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_objdump_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-objdump binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-objdump"

    strings:
        $s1 = "      --disassembler-color=terminal  Enable disassembler color output if displaying on a terminal." ascii // found in 1/456 binaries
        $s2 = "      --show-all-symbols         When disassembling, display all symbols at a given address" ascii // found in 1/456 binaries
        $s3 = " # Name     paddr    vaddr    size     scnptr   relptr   lnnoptr   nrel nlnno   Flags" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_ranlib_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-ranlib binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-ranlib"

    strings:
        $s1 = "Usage: %s [emulation options] [-]{dmpqrstx}[abcDfilMNoOPsSTuvV] [--plugin <name>] [member-name] [cou" ascii // found in 2/456 binaries
        $s2 = "  [u]          - only replace files that are newer than current archive contents" ascii // found in 2/456 binaries
        $s3 = "`u' is not meaningful with the `D' option - replacement will always happen." ascii // found in 2/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_readelf_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-readelf binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-readelf"

    strings:
        $s1 = "possibly corrupt ELF file header - it has a non-zero section header offset, but no section headers" ascii // found in 1/456 binaries
        $s2 = "    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend" ascii // found in 1/456 binaries
        $s3 = ", gnu calling co, reduced fp mod, 64-bit doubles, relocatable mo, Kalray VLIW kv, unknown KVX MP" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_size_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-size binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-size"

    strings:
        $s1 = "  -o|-d|-x  --radix={8|10|16}         Display numbers in octal, decimal or hex" ascii // found in 1/456 binaries
        $s2 = "  -A|-B|-G  --format={sysv|berkeley|gnu}  Select output style (default is %s)" ascii // found in 1/456 binaries
        $s3 = "  -t        --totals                  Display the total sizes (Berkeley only)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_strings_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-strings binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-strings"

    strings:
        $s1 = "  -a - --all                Scan the entire file, not just the data section [default]" ascii // found in 1/456 binaries
        $s2 = "  -U {d|s|i|x|e|h}          Specify how to treat UTF-8 encoded unicode characters" ascii // found in 1/456 binaries
        $s3 = "  -t --radix={o,d,x}        Print the location of the string in base 8, 10 or 16" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_x86_64_linux_gnu_strip_Binary {
    meta:
        description = "Track /bin/x86_64-linux-gnu-strip binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/x86_64-linux-gnu-strip"

    strings:
        $s1 = "local, global, export, debug, function, weak, section, constructor, warning, indirect, file, object," ascii // found in 2/456 binaries
        $s2 = "alloc, load, noload, readonly, debug, code, data, rom, exclude, contents, merge, strings, (COFF spec" ascii // found in 2/456 binaries
        $s3 = "                                   Produce deterministic output when stripping archives (default)" ascii // found in 2/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_xargs_Binary {
    meta:
        description = "Track /bin/xargs binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/xargs"

    strings:
        $s1 = "Execution of xargs will continue now, and it will try to read its input and run commands; if this is" ascii // found in 1/456 binaries
        $s2 = "WARNING: a NUL character occurred in the input.  It cannot be passed through in the argument list.  " ascii // found in 1/456 binaries
        $s3 = "Invalid input delimiter specification %s: the delimiter must be either a single character or an esca" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_xgettext_Binary {
    meta:
        description = "Track /bin/xgettext binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/xgettext"

    strings:
        $s1 = "<its:rules xmlns:its=\"http://www.w3.org/2005/11/its\"           version=\"2.0\">  <its:translateRule se" ascii // found in 1/456 binaries
        $s2 = "Workaround: If the msgid is a sentence, change the wording of the sentence; otherwise, use contexts " ascii // found in 1/456 binaries
        $s3 = "Although being used in a format string position, the %s is not a valid %s format string. Reason: %s" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_xz_Binary {
    meta:
        description = "Track /bin/xz binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/xz"

    strings:
        $s1 = "Reduced the number of threads from %s to one. The automatic memory usage limit of %s MiB is still be" ascii // found in 1/456 binaries
        $s2 = "%s: Null character found when reading filenames; maybe you meant to use `--files0' instead of `--fil" ascii // found in 1/456 binaries
        $s3 = "Adjusted LZMA%c dictionary size from %s MiB to %s MiB to not exceed the memory usage limit of %s MiB" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_yasm_Binary {
    meta:
        description = "Track /bin/yasm binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/yasm"

    strings:
        $s1 = "warning: can open only one input file, only the last file will be processed" ascii // found in 1/456 binaries
        $s2 = "warning: can output to only one object file, last specified used" ascii // found in 1/456 binaries
        $s3 = "warning: can output to only one error file, last specified used" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_yes_Binary {
    meta:
        description = "Track /bin/yes binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/yes"

    strings:
        $s1 = "Repeatedly output a line with all specified STRING(s), or 'y'." ascii // found in 1/456 binaries
        $s2 = "2524650b81f9deb4cfda20b876d60d7cd7aaff.debug" ascii // found in 1/456 binaries
        $s3 = "Usage: %s [STRING]..." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_ytasm_Binary {
    meta:
        description = "Track /bin/ytasm binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/ytasm"

    strings:
        $s1 = "w0=none, w1=w2=warnings on, w-xxx/w+xxx=disable/enable warning xxx" ascii // found in 1/456 binaries
        $s2 = "Copyright (c) 2001-2010 Peter Johnson and other Yasm developers." ascii // found in 1/456 binaries
        $s3 = "Jam in an assemble directive CMD (eg. /jIDEAL) (not supported)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_zdump_Binary {
    meta:
        description = "Track /bin/zdump binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/zdump"

    strings:
        $s1 = "  -c [L,]U   Start at year L (default -500), end before year U (default 2500)" ascii // found in 1/456 binaries
        $s2 = "  -t [L,]U   Start at time L, end before time U (in seconds since 1970)" ascii // found in 1/456 binaries
        $s3 = "  -i         List transitions briefly (format is experimental)" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_zip_Binary {
    meta:
        description = "Track /bin/zip binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/zip"

    strings:
        $s1 = "zip [-options] [-b path] [-t mmddyyyy] [-n suffixes] [zipfile list] [-xi list]" ascii // found in 1/456 binaries
        $s2 = "  -0   store only                   -l   convert LF to CR LF (-ll CR LF to LF)" ascii // found in 1/456 binaries
        $s3 = "    zip [-shortopts ...] [--longopt ...] [zipfile [path path ...]] [-xi list]" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_zipcloak_Binary {
    meta:
        description = "Track /bin/zipcloak binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/zipcloak"

    strings:
        $s1 = "  -d  --decrypt      decrypt encrypted entries (copy if given wrong password)" ascii // found in 1/456 binaries
        $s2 = "  the default action is to encrypt all unencrypted entries in the zip file" ascii // found in 1/456 binaries
        $s3 = "  -q  --quiet        quiet operation, suppress some informational messages" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_zipinfo_Binary {
    meta:
        description = "Track /bin/zipinfo binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/zipinfo"

    strings:
        $s1 = "         match directory separator /, but ** does.  Allows matching at specific" ascii // found in 2/456 binaries
        $s2 = "%s  -O CHARSET  specify a character encoding for DOS, Windows and OS/2 archives" ascii // found in 2/456 binaries
        $s3 = "  -I CHARSET  [UNIX] Specify a character encoding for UNIX and other archives." ascii // found in 2/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_zipnote_Binary {
    meta:
        description = "Track /bin/zipnote binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/zipnote"

    strings:
        $s1 = "  \"@ name\" can be followed by an \"@=newname\" line to change the name" ascii // found in 1/456 binaries
        $s2 = "  the default action is to write the comments in zipfile to stdout" ascii // found in 1/456 binaries
        $s3 = "     ... then you edit the comments, save, and exit ..." ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}

rule Known_Good_Linux_zipsplit_Binary {
    meta:
        description = "Track /bin/zipsplit binary by unique strings"
        author = "AutoGen"
        date = "2025-05-30"
        version = "1.0"
        file_type = "ELF"
        tlp = "WHITE"
        scope = "tracking"
        path = "/bin/zipsplit"

    strings:
        $s1 = "  -i   make index (zipsplit.idx) and count its size against first zip file" ascii // found in 1/456 binaries
        $s2 = "  -r   leave room for \"room\" bytes on the first disk (default = 0)" ascii // found in 1/456 binaries
        $s3 = "Usage:  zipsplit [-tipqs] [-n size] [-r room] [-b path] zipfile" ascii // found in 1/456 binaries

    condition:
        ELF_Structure and all of them
}
