// 📄 대상 확장자: .mp4, .avi, .mp3, .wav, .mkv
// 🧩 대상 파일: 오디오 및 비디오 미디어 파일
// 🎯 탐지 목적: 메타데이터에 명령어, URL, 스크립트, 실행 정보 등이 포함된 경우 탐지

rule Media_Metadata_With_Suspicious_Commands
{
    meta:
        description = "미디어 파일 메타데이터 내 명령어 또는 실행 정보 포함"
        author = "Seo"

    strings:
        $cmd = "cmd.exe" nocase
        $powershell = "powershell" nocase
        $sh = "/bin/sh" nocase
        $exec = "Exec(" nocase

    condition:
        any of them
}

rule Media_Metadata_With_URL_or_IP
{
    meta:
        description = "미디어 파일 메타데이터에 URL 또는 IP 주소가 포함됨"
        author = "Seo"

    strings:
        $url1 = "http://" nocase
        $url2 = "https://" nocase
        $ip = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/

    condition:
        any of them
}

rule Media_Metadata_With_Script_Extensions
{
    meta:
        description = "미디어 메타데이터에 .vbs, .ps1, .js 등 실행 스크립트 확장자가 포함됨"
        author = "Seo"

    strings:
        $vbs = ".vbs" nocase
        $ps1 = ".ps1" nocase
        $js = ".js" nocase
        $bat = ".bat" nocase
        $lnk = ".lnk" nocase

    condition:
        any of them
}

