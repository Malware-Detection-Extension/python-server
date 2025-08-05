// 📄 대상 확장자: .doc, .docm
// 🧩 대상 프로그램: Microsoft Word
// 🎯 탐지 목적: 매크로 함수 + 악성 VBA 패턴 탐지

rule Suspicious_Doc_Macro
{
    meta:
        description = "Word 문서 내 매크로 또는 의심스러운 VBA 함수 탐지"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }     // OLE2 문서 시그니처 (.doc)
        $zip = { 50 4B 03 04 }                 // ZIP 기반 문서 (.docx, .docm)

        $macro1 = "Auto_Open" ascii wide nocase
        $macro2 = "Document_Open" ascii wide nocase
        $macro3 = "Workbook_Open" ascii wide nocase

        $vba1 = "Shell" ascii wide nocase
        $vba2 = "CreateObject" ascii wide nocase
        $vba3 = "GetObject" ascii wide nocase
        $vba4 = "URLDownloadToFile" ascii wide nocase
        $vba5 = "WScript.Shell" ascii wide nocase

    condition:
        (1 of ($ole, $zip)) and (1 of ($macro*)) and (1 of ($vba*))
}

rule Suspicious_Doc_AutoExecution
{
    meta:
        description = "문서 열람 시 자동 실행되는 매크로 탐지"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $auto1_ascii = "Auto_Open" ascii nocase
        $auto1_wide  = "Auto_Open" wide nocase
        $doc1_ascii  = "Document_Open" ascii nocase
        $doc1_wide   = "Document_Open" wide nocase
        $work1_ascii = "Workbook_Open" ascii nocase
        $work1_wide  = "Workbook_Open" wide nocase

    condition:
        any of them
}

rule Suspicious_Doc_VBA_Functions
{
    meta:
        description = "VBA 내 악성 가능성이 높은 함수 사용 탐지"
        author = "Seo"
        severity = "medium"
        category = "document"

    strings:
        $vba1 = "Shell" ascii wide nocase
        $vba2 = "CreateObject" ascii wide nocase
        $vba3 = "GetObject" ascii wide nocase
        $vba4 = "URLDownloadToFile" ascii wide nocase
        $vba5 = "WScript.Shell" ascii wide nocase

    condition:
        2 of ($vba*)
}

rule DOC_Uses_DDE
{
    meta:
        description = "Word 문서에서 DDE 명령 사용 탐지"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $dde1 = "DDEAUTO" ascii nocase
        $dde2 = "DDE" ascii nocase
        $cmd = "cmd.exe" ascii nocase

    condition:
        $dde1 or ($dde2 and $cmd)
}

rule DOC_Enc_Powershell
{
    meta:
        description = "Base64로 인코딩된 powershell 명령 탐지"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $b64 = "FromBase64String" ascii nocase
        $iex = "IEX" ascii nocase
        $ps = "powershell" ascii nocase

    condition:
        2 of them
}

rule DOC_Social_Engineering_Strings
{
    meta:
        description = "악성 lure 문서에 흔한 단어 포함"
        author = "Seo"
        severity = "low"
        category = "document"

    strings:
        $inv = "invoice" ascii nocase
        $pay = "payment" ascii nocase
        $acc = "account" ascii nocase
        $pass = "password" ascii nocase

    condition:
        2 of them
}

rule DOC_Embedded_PE
{
    meta:
        description = "문서 안에 PE 실행파일 시그니처가 숨어 있을 경우"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $mz = { 4D 5A } // "MZ"

    condition:
        $mz
}
