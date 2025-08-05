// 📄 대상 확장자: .zip, .rar, .7z
// 🧩 대상 파일: 압축 파일 내부에 포함된 실행파일 또는 스크립트
// 🎯 탐지 목적: 압축 파일에 은닉된 PE 실행파일, 스크립트, 악성 파일 탐지

rule Archive_With_PE_File
{
    meta:
        description = "압축파일 내부에 PE 실행파일이 존재"
        author = "Seo"
        reference = "https://attack.mitre.org/techniques/T1027/001/"
        filetype = "ZIP or RAR"

    strings:
        $mz = "MZ"
        $pe = "This program cannot be run in DOS mode"
        $exe_ext = ".exe" nocase
        $dll_ext = ".dll" nocase

    condition:
        (uint32(0) == 0x504B0304 or uint32(0) == 0x52617221) and
        (1 of ($mz, $pe) or any of ($exe_ext, $dll_ext))
}

rule Archive_With_Suspicious_Script
{
    meta:
        description = "압축파일 내 .vbs, .js, .bat 등 스크립트 존재"
        author = "Seo"
        reference = "https://attack.mitre.org/techniques/T1059/005/"

    strings:
        $vbs = ".vbs" nocase
        $js = ".js" nocase
        $bat = ".bat" nocase
        $cmd = ".cmd" nocase
        $ps1 = ".ps1" nocase

    condition:
        (uint32(0) == 0x504B0304 or uint32(0) == 0x52617221) and
        any of them
}

rule Archive_With_Encoded_PE_AutoIt
{
    meta:
        description = "압축파일 내 AutoIt 또는 Base64 인코딩된 PE 페이로드"
        author = "Seo"

    strings:
        $autoit = "AutoIt3.exe" nocase
        $b64long = /TVqQAAMAAAAEAAAA.{100,}/  // MZ = TVqQ, PE 파일 Base64 형태

    condition:
        (uint32(0) == 0x504B0304 or uint32(0) == 0x52617221)
        and any of them
}

rule Archive_With_Lure_Doc_And_Executable
{
    meta:
        description = "압축파일에 Word lure 문서와 실행파일이 함께 있는 경우"
        author = "Seo"

    strings:
        $doc = ".doc" nocase
        $docx = ".docx" nocase
        $exe = ".exe" nocase
        $lnk = ".lnk" nocase  // 바로가기 파일도 종종 사용됨

    condition:
        (uint32(0) == 0x504B0304 or uint32(0) == 0x52617221)
        and (1 of ($doc, $docx))
        and (1 of ($exe, $lnk))
}

rule Archive_With_Disguised_Executable
{
    meta:
        description = "파일 이름이 이중 확장자로 위장된 실행파일 포함 (.jpg.exe 등)"
        author = "Seo"

    strings:
        $jpg_exe = ".jpg.exe" nocase
        $pdf_exe = ".pdf.exe" nocase
        $txt_exe = ".txt.exe" nocase
        $pdf_lnk = ".pdf.lnk" nocase

    condition:
        (uint32(0) == 0x504B0304 or uint32(0) == 0x52617221)
        and any of them
}
