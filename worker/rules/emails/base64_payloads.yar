// 📄 대상 확장자: .eml, .msg, .txt (이메일 원문 혹은 저장된 본문 파일)
// 🧩 대상 파일: 이메일 본문 또는 첨부파일 내용
// 🎯 탐지 목적: Base64로 인코딩된 실행파일, 스크립트, 매크로 등이 포함된 경우 탐지

rule Email_With_Base64_PE
{
    meta:
        description = "이메일 내 Base64로 인코딩된 PE 파일"
        author = "Seo"
        reference = "https://attack.mitre.org/techniques/T1027/003/"

    strings:
        $mz_b64 = "TVqQAAMAAAAEAAAA" // 'MZ'로 시작하는 PE 파일의 base64
        $dos_b64 = "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGU=" // 'This program cannot be run in DOS mode'
        $exe_ext_b64 = "LmV4ZQ==" // '.exe'
        $dll_ext_b64 = "LmRsbA==" // '.dll'

    condition:
        any of them
}

rule Email_With_Base64_Script
{
    meta:
        description = "이메일 내 Base64 인코딩된 스크립트 (.vbs, .ps1 등)"
        author = "Seo"

    strings:
        $vbs_b64 = "LnZicw=="  // .vbs
        $bat_b64 = "LmJhdA=="  // .bat
        $ps1_b64 = "LnBzMQ=="  // .ps1
        $cmd_b64 = "LmNtZA=="  // .cmd
        $wscript_b64 = "V1NjcmlwdC5TaGVsbA=="  // WScript.Shell

    condition:
        any of them
}

rule Email_With_Long_Base64_Block
{
    meta:
        description = "Base64 문자열이 이메일 본문에 비정상적으로 긴 경우 (200자 이상)"
        author = "Seo"

    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/

    condition:
        $b64
}

rule Email_With_Base64_Execution_Code
{
    meta:
        description = "Base64 문자열을 FromBase64String으로 실행하는 코드 포함"
        author = "Seo"

    strings:
        $b64_hint = /[A-Za-z0-9+\/]{100,}={0,2}/
        $decode = "FromBase64String" nocase
        $invoke = "Invoke-Expression" nocase

    condition:
        $b64_hint and any of ($decode, $invoke)
}

rule HTML_Email_With_Base64_URL
{
    meta:
        description = "HTML 이메일 내 Base64 인코딩된 URL 포함"
        author = "Seo"

    strings:
        $data_url = "data:text/html;base64," nocase
        $html_tag = "<html" nocase

    condition:
        $data_url and $html_tag
}

rule Email_With_Encoded_Compressed_Payload
{
    meta:
        description = "Base64와 함께 gzip/zlib 헤더가 함께 존재하는 경우"
        author = "Seo"

    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
        $gzip = { 1F 8B }  // gzip magic number
        $zlib = { 78 9C }  // zlib 압축

    condition:
        $b64 and any of ($gzip, $zlib)
}
