// 📄 대상 확장자: .jpg, .jpeg, .png, .gif
// 🧩 대상 파일: 이미지 파일 (JPEG, PNG, GIF 등)
// 🎯 탐지 목적: 이미지 내부에 은닉된 악성 페이로드 탐지 (PE 파일, Base64, EXIF 등)

rule Hidden_PE_Payload_In_Image
{
    meta:
        description = "이미지 내부에 PE 실행파일이 숨어있는 경우 탐지"
        author = "Seo"
        filetype = "jpg|png|gif"

    strings:
        $mz = "MZ"                 // PE 파일의 시작 시그니처
        $pe = "This program cannot be run in DOS mode"
        $padding = { 00 00 00 00 00 00 00 00 00 00 }  // 과도한 패딩 (숨기기 위한)

    condition:
        (uint16(0) == 0xFFD8 or uint32(0) == 0x89504E47 or uint32(0) == 0x47494638)
        and any of ($mz, $pe, $padding)

}

rule Image_With_Base64_Encoded_Script
{
    meta:
        description = "Base64 인코딩된 스크립트가 이미지에 삽입된 경우"
        author = "Seo"
        reference = "https://attack.mitre.org/techniques/T1027/003/"

    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
        $hint1 = "powershell" nocase
        $hint2 = "FromBase64String" nocase

    condition:
        uint16(0) == 0xFFD8 or uint32(0) == 0x89504E47
        and $b64 and 1 of ($hint1, $hint2)
}

rule Suspicious_EXIF_Metadata
{
    meta:
        description = "EXIF 메타데이터에 명령어나 URL이 포함된 이미지"
        author = "Seo"

    strings:
        $cmd = "cmd.exe" nocase
        $url = "http://" nocase
        $ps = "powershell" nocase
        $vbs = ".vbs" nocase

    condition:
        uint16(0) == 0xFFD8  // JPEG
        and any of them
}
