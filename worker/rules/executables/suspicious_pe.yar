// 📄 대상 확장자: .exe, .dll
// 🧩 대상 파일: Windows PE 실행파일
// 🎯 탐지 목적: 악성 의심 행동 (API 호출, anti-VM, 비정상 섹션 등) 포함 PE 탐지

import "pe"

rule PE_Suspicious_APIs
{
    meta:
        description = "악성코드에서 자주 사용되는 위험 API 호출 포함"
        author = "Seo"

    strings:
        $v_alloc = "VirtualAlloc" nocase
        $v_protect = "VirtualProtect" nocase
        $wpm = "WriteProcessMemory" nocase
        $ct = "CreateThread" nocase
        $peb = "IsDebuggerPresent" nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule PE_Anti_VM_Strings
{
    meta:
        description = "VM 또는 샌드박스 탐지 우회용 문자열 포함"
        author = "Seo"

    strings:
        $vm1 = "VBoxGuest" nocase
        $vm2 = "vmtoolsd.exe" nocase
        $vm3 = "qemu" nocase
        $vm4 = "SbieDll.dll" nocase  // Sandboxie

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PE_Suspicious_Section_Names
{
    meta:
        description = "의심스러운 섹션 이름 (.text, .data 제외)"
        author = "Seo"

    strings:
        $s1 = ".textbss"
        $s2 = ".xyz"
        $s3 = ".aspack"
        $s4 = ".enc"
        $s5 = ".mpress"

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule PE_Exec_From_Nonstandard_Entry
{
    meta:
        description = "PE EntryPoint가 코드 영역이 아닌 곳에 위치"
        author = "Seo"

    condition:
        uint16(0) == 0x5A4D and
        pe.entry_point < pe.sections[0].raw_data_offset or
        pe.entry_point > pe.sections[pe.number_of_sections - 1].raw_data_offset + pe.sections[pe.number_of_sections - 1].raw_data_size
}
