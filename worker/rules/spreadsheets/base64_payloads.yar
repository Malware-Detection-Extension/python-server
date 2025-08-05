// 📄 대상 확장자: .xls, .xlsx, .xlsm
// 🧩 대상 파일: Microsoft Excel 스프레드시트
// 🎯 탐지 목적: 매크로나 셀 내부에 숨겨진 Base64 인코딩 악성 코드 탐지

rule Excel_With_Base64_PE_Payload
{
    meta:
        description = "Excel 문서에 Base64로 인코딩된 PE (실행파일) 포함"
        author = "Seo"

    strings:
        $mz_b64 = "TVqQAAMAAAAEAAAA"  // 'MZ' 헤더 base64
        $pe_b64 = "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGU="  // DOS mode 문자열
        $exe_b64 = "LmV4ZQ=="  // .exe
        $dll_b64 = "LmRsbA=="  // .dll

    condition:
        any of them
}

rule Excel_With_Base64_Script
{
    meta:
        description = "Base64로 인코딩된 스크립트(.vbs, .js, .ps1 등)가 포함된 경우"
        author = "Seo"

    strings:
        $vbs_b64 = "LnZicw=="  // .vbs
        $ps1_b64 = "LnBzMQ=="  // .ps1
        $bat_b64 = "LmJhdA=="  // .bat
        $cmd_b64 = "LmNtZA=="  // .cmd
        $wscript_b64 = "V1NjcmlwdC5TaGVsbA=="  // WScript.Shell

    condition:
        any of them
}

rule Excel_With_Suspicious_Base64_Block
{
    meta:
        description = "비정상적으로 긴 base64 문자열을 포함한 Excel 문서"
        author = "Seo"

    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/

    condition:
        $b64
}
