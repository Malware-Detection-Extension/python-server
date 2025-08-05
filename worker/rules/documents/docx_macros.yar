// 📄 대상 확장자: .docx, .docm
// 🧩 대상 파일: Word ZIP 기반 OOXML 문서
// 🎯 탐지 목적: ZIP 내부에 포함된 vbaProject.bin 또는 악성 XML 내 외부 실행 흔적 탐지

rule DOCX_Contains_MacroProject
{
    meta:
        description = "docx/docm 파일 내 vbaProject.bin 존재 여부"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $zip_header = { 50 4B 03 04 }                  // ZIP 시그니처
        $vba_full = "word/vbaProject.bin" ascii        // 전체 경로
        $vba_short = "vbaProject.bin" ascii            // 경로 없이도 커버

    condition:
        $zip_header at 0 and any of ($vba*)
}

rule DOCX_Suspicious_XML_Strings
{
    meta:
        description = "Word XML 구조 내 외부 실행 관련 문자열 포함"
        author = "Seo"
        severity = "medium"
        category = "document"

    strings:
        $url = /http[s]?:\/\/[^\s]+/ ascii
        $cmd = "cmd.exe" ascii nocase
        $ps1 = "powershell" ascii nocase
        $script = "<script" ascii nocase    // FP 방지를 위해 구체화

    condition:
        2 of them
}

rule DOCX_External_Relationship
{
    meta:
        description = "docx 문서 내 외부 관계 파일 또는 링크 포함 여부"
        author = "Seo"
        severity = "medium"
        category = "document"

    strings:
        $rels = "_rels/.rels" ascii
        $external = "ExternalRelationship" ascii
        $target = /Target=\"http[s]?:\/\/[^\"]+/ ascii

    condition:
        any of them
}

rule DOCX_OLE_Exploit_Like
{
    meta:
        description = "CVE-2017-0199 유형의 OLE 객체 삽입 가능성"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $ole = "oleObject" ascii nocase
        $packager = "packager.dll" ascii nocase
        $fileurl = /file:\/\/[^\s]+/ ascii

    condition:
        2 of them
}

rule DOCX_Embedded_Suspicious_Extensions
{
    meta:
        description = "docx 내부에 exe, js, vbs, ps1 등 의심 확장자 포함"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $exe = ".exe" ascii
        $js = ".js" ascii
        $vbs = ".vbs" ascii
        $ps1 = ".ps1" ascii

    condition:
        2 of them
}
