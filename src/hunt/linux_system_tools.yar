import "elf"

rule Hunt_Network_Diagnostic_Tools
{
    meta:
        description = "Detects network diagnostic utilities like ping, nslookup, and dig"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.NetworkTools"
        mitre_attack = "T1016"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $ping = "minimal interval for broadcast ping for user must be >= %d ms" ascii
        $nslookup = "nslookup [-opt ...] host server # just look up 'host' using 'server'" ascii
        $dig = "+[no]https-get      (Use GET instead of default POST method while using HTTPS)" ascii
    condition:
        elf.type == elf.ET_EXEC and any of ($ping, $nslookup, $dig)
}

rule Hunt_Base64_Encoding_Tools
{
    meta:
        description = "Detects base64/base32 encoding or decoding utilities"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.EncodingTools"
        mitre_attack = "T1140"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $base64_debug = "1ce20eb3a22cba18521f4a86c723567047b723.debug" ascii
        $base32_debug = "b5238c7cd26c6d5b494b61f3ae4d7f96d8974e.debug" ascii
        $alphabet = {41 42 43 44 45 46 47 48 49 4A 4B 4C 4D}
    condition:
        elf.type == elf.ET_EXEC and ( ($base64_debug and $alphabet) or $base32_debug )
}

rule Hunt_Container_Runtime_Tools
{
    meta:
        description = "Detects container runtime related utilities"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.ContainerTools"
        mitre_attack = "T1055"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $docker = "docker" ascii
        $nsenter = "-Z, --follow-context   set SELinux context according to --target PID" ascii
        $unshare = "--monotonic <offset>      set clock monotonic offset (seconds) in time namespaces" ascii
        $nspawn = "systemd-nspawn" ascii
    condition:
        elf.type == elf.ET_EXEC and 2 of ($docker, $nsenter, $unshare, $nspawn)
}

rule Hunt_Backup_And_Archive_Tools
{
    meta:
        description = "Detects backup and compression utilities that could exfiltrate data"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.BackupTools"
        mitre_attack = "T1560"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $tar = "preserve access times on dumped files, either by restoring the times" ascii
        $gzip = "--synchronous synchronous output (safer if system crashes, but slower)" ascii
        $bzip2 = "it under the terms set out in the LICENSE file, which is included" ascii
        $xz = "Adjusted LZMA%c dictionary size from %s MiB to %s MiB" ascii
    condition:
        elf.type == elf.ET_EXEC and ( ($tar and $gzip) or $bzip2 or $xz )
}

rule Hunt_Shell_Interpreters
{
    meta:
        description = "Detects common shell interpreters"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.Shells"
        mitre_attack = "T1059"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $bash = "bind [-lpsvPSVX] [-m keymap] [-f filename]" nocase ascii wide
        $dash = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" nocase ascii wide
        $sh = "/bin/sh" nocase ascii wide
    condition:
        elf.type == elf.ET_EXEC and any of ($bash, $dash, $sh)
}

rule Hunt_System_Monitoring_Tools
{
    meta:
        description = "Detects advanced system monitoring utilities"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.MonitoringTools"
        mitre_attack = "T1082"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $regex = /\b(cpu|memory|process|disk|network)\s+(usage|monitor|stat)/ nocase
        $top = "%s~3%#5.1f ~2us,~3%#5.1f ~2sy,~3%#5.1f ~2ni" ascii
        $htop = "htop" ascii
        $vmstat = "--procs-- -----------------------memory----------------------" ascii
        $iostat = "Device:" ascii
    condition:
        elf.type == elf.ET_EXEC and $regex and 3 of ($top, $htop, $vmstat, $iostat)
}

rule Hunt_Cryptographic_Tools
{
    meta:
        description = "Detects cryptographic tools like OpenSSL and GPG"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.CryptoTools"
        mitre_attack = "T1486"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $openssl = "assertion failed: (family == AF_UNSPEC || family == BIO_ADDRINFO_family" ascii
        $gpg_key = /[A-F0-9]{8}[A-F0-9]{8}/
        $rsa = {30 82 ?? ?? 02 01 00}
    condition:
        elf.type == elf.ET_EXEC and ( $openssl or ($gpg_key and $rsa) )
}

rule Hunt_Build_System_Tools
{
    meta:
        description = "Detects build tools indicating CI/CD capabilities"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.BuildTools"
        mitre_attack = "T1127"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $make = "target-specific order-only second-expansion else-if" ascii
        $cmake = "];GRAPHVIZ_GRAPH_NGRAPHVIZ_GRAPH_HGRAPHVIZ" ascii
        $ninja = "ninja executable version (%s) greater than build file" ascii
        $gcc = "gcc" ascii
    condition:
        elf.type == elf.ET_EXEC and 3 of ($make, $cmake, $ninja, $gcc)
}

rule Hunt_Time_Manipulation_Tools
{
    meta:
        description = "Detects time-related utilities"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.TimeTools"
        mitre_attack = "T1070"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $date = "%:::z  numeric time zone with : to necessary precision" ascii
        $timedatectl = "Warning: The system is configured to read the RTC time" ascii
        $touch = "-t STAMP               use [[CC]YY]MMDDhhmm[.ss]" ascii
    condition:
        elf.type == elf.ET_EXEC and any of ($date, $timedatectl, $touch)
}

rule Hunt_Process_Management_Suite
{
    meta:
        description = "Detects presence of complete process management toolkit"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.ProcessTools"
        mitre_attack = "T1057"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $ps = "pid,tname,majflt,minflt,m_trs,m_drs,m_size" ascii
        $kill = "-q, --queue <value>    integer value to be sent with the signal" ascii
        $pkill = "pattern that searches for process name longer than 15 characters" ascii
        $killall = "killall" ascii
    condition:
        elf.type == elf.ET_EXEC and $ps and 2 of ($kill, $pkill, $killall)
}

rule Hunt_File_Permission_Tools
{
    meta:
        description = "Detects tools that can modify file permissions"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.PermissionTools"
        mitre_attack = "T1222"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $chmod = "Rcfvr::w::x::X::s::t::u::g::o::a::,::+::=::0::1::2::3::4::5::6::7::" ascii
        $chown = "its current owner and/or group match those specified" ascii
        $perm = {01 FF}
    condition:
        elf.type == elf.ET_EXEC and $chmod and $chown and $perm
}

rule Hunt_User_Management_Tools
{
    meta:
        description = "Detects user management utilities"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.UserTools"
        mitre_attack = "T1136"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $useradd = "useradd" ascii
        $passwd = "You should set a password with usermod -p" ascii
        $chage = "-E, --expiredate EXPIRE_DATE  set account expiration date" ascii
        $usermod = "usermod" ascii
    condition:
        elf.type == elf.ET_EXEC and 3 of ($useradd, $passwd, $chage, $usermod)
}

rule Hunt_Systemd_Service_Tools
{
    meta:
        description = "Detects systemd management utilities"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.SystemdTools"
        mitre_attack = "T1569"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $systemctl = "+PAM +AUDIT +SELINUX +APPARMOR +IMA +SMACK" ascii
        $pattern = {73 79 73 74 65 6D 64 2D ?? ?? ?? ??}
        $analyze = "Options --root= and --image= are only supported for" ascii
    condition:
        elf.type == elf.ET_EXEC and $systemctl and $analyze and $pattern
}

rule Hunt_Disk_Utility_Tools
{
    meta:
        description = "Detects disk management utilities"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.DiskTools"
        mitre_attack = "T1000"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $lsblk = "-M, --merge          group parents of sub-trees" ascii
        $fdisk = "fdisk" ascii
        $disk = "disk" ascii
    condition:
        elf.type == elf.ET_EXEC and ($lsblk or $fdisk) and $disk and filesize < 200KB and filesize > 10KB
}

rule Hunt_Regex_Tool_Capabilities
{
    meta:
        description = "Detects tools that use regular expressions"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.RegexTools"
        mitre_attack = "T1106"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $pattern = /\/[^\/]+\/[gimsx]?/
        $grep = "-U, --binary              do not strip CR characters" ascii
        $sed = "specify the desired line-wrap length for the 'l' command" ascii
        $awk = "awk" ascii
    condition:
        elf.type == elf.ET_EXEC and $pattern and any of ($grep, $sed, $awk)
}

rule Hunt_Binary_Analysis_Tools
{
    meta:
        description = "Detects reverse engineering tools like readelf or objdump"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.AnalysisTools"
        mitre_attack = "T1027"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $readelf = "readelf" ascii
        $objdump = "--show-all-symbols         When disassembling" ascii
        $debug = ".debug" ascii
    condition:
        uint32(0) == 0x7F454C46 and ($readelf or $objdump) and $debug
}

rule Hunt_Log_Analysis_Tools
{
    meta:
        description = "Detects log parsing and analysis utilities"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.LogTools"
        mitre_attack = "T1071"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $journalctl = "Journal file %s has sealing enabled" ascii
        $dmesg = "--raw can be used together with --level" ascii
        $less = "less" ascii
        $more = "more" ascii
        $log = "log" nocase
        $journal = "journal" nocase
        $syslog = "syslog" nocase
        $message = "message" nocase
    condition:
        elf.type == elf.ET_EXEC and ( $journalctl or $dmesg or $less or $more ) and 2 of ($log, $journal, $syslog, $message)
}

rule Hunt_Script_Interpreters
{
    meta:
        description = "Detects scripting language interpreters"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.ScriptInterpreters"
        mitre_attack = "T1059"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $python = "Python runtime initialized with LC_CTYPE=C" nocase ascii
        $perl = "PERL_COPY_ON_WRITE PERL_DONT_CREATE_GVSV" nocase ascii
        $ruby = "ruby" nocase ascii
        $node = "V8" nocase ascii
    condition:
        elf.type == elf.ET_EXEC and any of ($python, $perl, $ruby, $node)
}

rule Hunt_Archive_Format_Tools
{
    meta:
        description = "Detects archive format handlers"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.ArchiveTools"
        mitre_attack = "T1560"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $zip_sig = {50 4B 03 04}
        $tar = "ustar" ascii
        $seven_sig = {37 7A BC AF 27 1C}
        $zip = "zip [-options] [-b path] [-t mmddyyyy]" ascii
        $unzip = "match directory separator /, but ** does" ascii
        $seven = "7z" ascii
    condition:
        elf.type == elf.ET_EXEC and ( ($zip_sig and ($zip or $unzip)) or ($seven_sig and $seven) or $tar )
}

rule Hunt_Security_Tool_Presence
{
    meta:
        description = "Detects security and forensic tools"
        author = "ThreatFlux"
        date = "2024-09-18"
        version = "1.0"
        hash = "N/A"
        file_type = "ELF"
        tlp = "WHITE"
        family = "Linux.SecurityTools"
        mitre_attack = "T1068"
        scope = "hunting"
        license = "MIT"
        references = "N/A"
    strings:
        $sudo = "a terminal is required to read the password" ascii
        $su = "user %s does not exist" ascii
        $audit = "audit" ascii
        $perm = "Rcfvr::w::x::X::s::t::u::g::o::a::,::+::=::0::1::2::3::4::5::6::7::" ascii
        $crypto = {30 82 ?? ?? 02 01 00}
    condition:
        elf.type == elf.ET_EXEC and $crypto and 3 of ($sudo, $su, $audit, $perm)
}

