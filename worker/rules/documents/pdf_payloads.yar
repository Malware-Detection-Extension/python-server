// 📄 대상 확장자: .pdf
// 🧩 대상 파일: PDF 문서
// 🎯 탐지 목적: PDF 문서에 포함된 악성 스크립트, 자동 실행 등 의심 동작 탐지

rule PDF_Embedded_JavaScript
{
    meta:
        description = "PDF에 포함된 JavaScript 코드 탐지"
        author = "Seo"
        severity = "high"
        category = "document"
        filetype = "pdf"

    strings:
        $js = "/JavaScript"
        $open_action = "/OpenAction"
        $aa = "/AA"  // Additional Actions
        $launch = "/Launch"

    condition:
        uint32(0) == 0x25504446 and 2 of them
}

rule PDF_With_Embedded_File
{
    meta:
        description = "PDF 내부에 첨부된 파일 탐지 (/EmbeddedFile)"
        author = "Seo"
        severity = "high"
        category = "document"
        filetype = "pdf"

    strings:
        $embed = "/EmbeddedFile"
        $filespec = "/Filespec"
        $stream = "stream"
        $exe = ".exe" nocase

    condition:
        uint32(0) == 0x25504446 and 2 of them
}

rule PDF_Contains_Suspicious_Keywords
{
    meta:
        description = "PDF에 흔히 사용되는 의심 명령어 탐지"
        author = "Seo"
        severity = "medium"
        category = "document"
        filetype = "pdf"

    strings:
        $cmd = "cmd.exe" nocase
        $ps = "powershell" nocase
        $bat = ".bat" nocase
        $vbs = ".vbs" nocase

    condition:
        uint32(0) == 0x25504446 and any of them
}