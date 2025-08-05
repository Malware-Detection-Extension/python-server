// 📄 대상 확장자: .vbs, .js, .bat, .ps1, .cmd
// 🧩 대상 파일: Windows 스크립트 및 명령어 실행 파일
// 🎯 탐지 목적: 실행, 다운로드, 인코딩, 우회 관련 악성 명령어 포함 여부 탐지

rule Script_Using_Download_Exec
{
    meta:
        description = "WScript.Shell 및 URLDownloadToFile API 등 다운로드 실행 시도"
        author = "Seo"

    strings:
        $shell = "WScript.Shell" nocase
        $run = ".Run(" nocase
        $urlmon = "URLDownloadToFile" nocase
        $powershell = "powershell -" nocase

    condition:
        2 of them
}

rule Script_Using_Obfuscation_Functions
{
    meta:
        description = "base64 디코딩, char-by-char 조립 등 난독화 시도 탐지"
        author = "Seo"

    strings:
        $fromB64 = "FromBase64String" nocase
        $xor = "xor" nocase
        $chr = "chr(" nocase
        $mid = "Mid(" nocase
        $eval = "eval(" nocase

    condition:
        any of them
}

rule Script_Invoking_Mimikatz_or_Creds
{
    meta:
        description = "Mimikatz, 암호 추출 또는 시스템 정보 수집 시도"
        author = "Seo"

    strings:
        $mimikatz = "Invoke-Mimikatz" nocase
        $lsass = "lsass" nocase
        $cred = "Get-Credential" nocase
        $dump = "sekurlsa" nocase
        $net_user = "net user" nocase

    condition:
        any of them
}

rule Script_Touches_Sensitive_Registry
{
    meta:
        description = "스크립트가 민감한 레지스트리 경로 접근 시도"
        author = "Seo"

    strings:
        $reg_run = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $reg_disable_defender = "DisableAntiSpyware"
        $reg_persistence = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

    condition:
        any of them
}
