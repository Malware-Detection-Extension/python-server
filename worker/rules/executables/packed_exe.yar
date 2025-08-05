// 📄 대상 확장자: .exe, .dll
// 🧩 대상 파일: Windows PE 실행파일
// 🎯 탐지 목적: UPX, ASPack, FSG, Themida, Nullsoft 등 패킹된 실행파일 탐지

rule Packed_PE_UPX
{
    meta:
        description = "UPX로 패킹된 PE 파일"
        author = "Seo"
        reference = "https://upx.github.io/"

    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $upx3 = "UPX2"
        $upx_mark = "UPX!" // 섹션 이름으로 존재

    condition:
        uint16(0) == 0x5A4D and // MZ
        any of them
}

rule Packed_PE_ASPack
{
    meta:
        description = "ASPack로 패킹된 PE 파일"
        author = "Seo"

    strings:
        $aspack1 = "ASPack" nocase
        $aspack2 = "aspackstub" nocase
        $aspack_sig = { 41 53 50 61 63 6B } // "ASPack"

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule Packed_PE_Themida
{
    meta:
        description = "Themida 패커 사용 PE 파일"
        author = "Seo"

    strings:
        $themida1 = "Themida" nocase
        $winlicense = "WinLicense" nocase
        $sig = { 54 68 65 6D 69 64 61 } // "Themida"

    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule Packed_PE_Suspicious_Sections
{
    meta:
        description = "비정상적인 섹션 이름 (UPX, .packed, .text 제외)"
        author = "Seo"

    strings:
        $sec1 = ".adata"
        $sec2 = ".rdata1"
        $sec3 = ".xyz"
        $sec4 = ".petite"
        $sec5 = ".boom"

    condition:
        uint16(0) == 0x5A4D and
        any of them
}