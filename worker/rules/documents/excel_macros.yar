// 📄 대상 확장자: .xls, .xlsx, .xlsm
// 🧩 대상 파일: Microsoft Excel 스프레드시트
// 🎯 탐지 목적: 매크로 자동 실행, 외부 객체 실행, DDE 악용 등 행위 기반 탐지

rule Excel_Macro_AutoExecution
{
    meta:
        description = "Excel 문서 내 자동 실행 매크로 함수 (Workbook_Open 등)"
        author = "Seo"
        severity = "high"
        category = "spreadsheets"

    strings:
        $open1 = "Workbook_Open" ascii wide nocase
        $open2 = "Auto_Open" ascii wide nocase
        $run   = "Application.Run" ascii wide nocase

    condition:
        any of them
}

rule Excel_Macro_Exec_Functions
{
    meta:
        description = "Excel 매크로에서 외부 실행 관련 함수 사용 (Shell, CreateObject 등)"
        author = "Seo"
        severity = "high"
        category = "spreadsheets"

    strings:
        $shell = "Shell" ascii wide nocase
        $obj1 = "CreateObject" ascii wide nocase
        $obj2 = "GetObject" ascii wide nocase
        $url1 = "URLDownloadToFile" ascii wide nocase
        $wsh  = "WScript.Shell" ascii wide nocase

    condition:
        2 of them
}

rule Excel_DDE_Exploit
{
    meta:
        description = "DDEAUTO 또는 DDE 명령을 포함한 Excel 문서 (DDE 공격)"
        author = "Seo"
        severity = "medium"
        category = "spreadsheets"

    strings:
        $dde1 = "DDEAUTO" ascii nocase
        $dde2 = "DDE" ascii nocase
        $cmd = "cmd.exe" ascii nocase
        $ps1 = "powershell" ascii nocase

    condition:
        1 of ($dde*) and 1 of ($cmd, $ps1)
}

rule Excel_XLM_Macrosheet_Present
{
    meta:
        description = "Excel 문서에 Excel 4.0 macrosheet 포함"
        author = "Seo"
        severity = "medium"
        category = "spreadsheets"

    strings:
        $xlm = "Macrosheet" ascii
        $xlm2 = "Sheet Type=\"Macro\"" ascii

    condition:
        any of them
}

rule Excel_XLM_AutoOpen
{
    meta:
        description = "Excel 4.0 매크로에서 Auto_Open 또는 GET.WORKSPACE 사용"
        author = "Seo"
        severity = "high"
        category = "spreadsheets"

    strings:
        $auto = "Auto_Open" ascii
        $getws = "GET.WORKSPACE" ascii
        $xcall = "RUN" ascii

    condition:
        2 of them
}

rule Excel_XLM_Hidden_Macrosheet
{
    meta:
        description = "숨겨진 상태의 Excel 4.0 macrosheet 탐지"
        author = "Seo"
        severity = "high"
        category = "spreadsheets"

    strings:
        $hidden1 = "Visible=\"0\"" ascii
        $hidden2 = "State=\"Hidden\"" ascii
        $macrosheet = "Macrosheet" ascii

    condition:
        $macrosheet and 1 of ($hidden*)
}
