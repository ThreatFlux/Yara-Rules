private rule ELF_Structure
{
    meta:
        description = "Detects valid, executable ELF files"
        reference_files = "minimal.elf (acb271fe7aeb41683ab79dd278431aca)"
        author = "ThreatFlux"
        date = "2024-12-31"
        version = "1.1"
        file_type = "ELF"

    condition:
        // Magic number check
        uint32be(0) == 0x7F454C46         // 0x7F 'ELF'
}