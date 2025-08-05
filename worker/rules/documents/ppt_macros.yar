// 📄 대상 확장자: .ppt, .pptx, .pptm
// 🧩 대상 파일: Microsoft PowerPoint 프레젠테이션
// 🎯 탐지 목적: 슬라이드 기반 자동 실행, 외부 실행 호출, 링크 실행 등 탐지

rule PPT_AutoExecution_Macro
{
    meta:
        description = "PowerPoint 문서 내 자동 실행 매크로 함수 (SlideShowBegin 등)"
        author = "Seo"
        severity = "high"
        category = "presentation"

    strings:
        $open1 = "Auto_Open" ascii wide nocase
        $open2 = "SlideShowBegin" ascii wide nocase
        $open3 = "PresentationOpen" ascii wide nocase

    condition:
        any of them
}

rule PPT_External_Launch_Strings
{
    meta:
        description = "외부 프로그램 실행 또는 링크 실행 시도"
        author = "Seo"
        severity = "high"
        category = "presentation"

    strings:
        $shell = "Shell" ascii wide nocase
        $url = /http[s]?:\/\/[^\s]+/ ascii wide
        $lnk = ".lnk" ascii wide nocase
        $exe = ".exe" ascii wide nocase

    condition:
        2 of them
}
