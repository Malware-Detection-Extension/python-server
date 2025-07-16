rule Suspicious_PE_Executable
{
    meta:
        description = "Detects suspicious PE executable patterns"
        author = "Security Team"
        date = "2025-01-01"
        severity = "high"
    
    strings:
        $mz_header = { 4D 5A }
        $pe_header = { 50 45 00 00 }
        
        // Suspicious API calls
        $api1 = "CreateRemoteThread" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "VirtualAllocEx" ascii wide
        $api4 = "SetWindowsHookEx" ascii wide
        $api5 = "GetProcAddress" ascii wide
        $api6 = "LoadLibrary" ascii wide
        
        // Registry manipulation
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $reg2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        
        // Suspicious strings
        $sus1 = "rundll32.exe" ascii wide
        $sus2 = "powershell.exe" ascii wide
        $sus3 = "cmd.exe" ascii wide
        
    condition:
        $mz_header at 0 and $pe_header and 
        (3 of ($api*) or 1 of ($reg*) or 2 of ($sus*))
}

rule Suspicious_Script_Files
{
    meta:
        description = "Detects suspicious script files"
        author = "Security Team"
        severity = "medium"
    
    strings:
        // PowerShell obfuscation
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "DownloadString" ascii wide nocase
        $ps3 = "IEX" ascii wide nocase
        $ps4 = "Invoke-Expression" ascii wide nocase
        $ps5 = "Base64" ascii wide nocase
        $ps6 = "FromBase64String" ascii wide nocase
        
        // JavaScript suspicious patterns
        $js1 = "eval(" ascii wide nocase
        $js2 = "unescape(" ascii wide nocase
        $js3 = "String.fromCharCode" ascii wide nocase
        $js4 = "document.write" ascii wide nocase
        
        // VBScript suspicious patterns
        $vbs1 = "CreateObject" ascii wide nocase
        $vbs2 = "WScript.Shell" ascii wide nocase
        $vbs3 = "Shell.Application" ascii wide nocase
        
        // Batch file suspicious patterns
        $bat1 = "@echo off" ascii wide nocase
        $bat2 = "attrib +h" ascii wide nocase
        $bat3 = "taskkill" ascii wide nocase
        
    condition:
        (3 of ($ps*)) or (2 of ($js*)) or (2 of ($vbs*)) or (2 of ($bat*))
}

rule Suspicious_Network_Activity
{
    meta:
        description = "Detects files with suspicious network activity patterns"
        author = "Security Team"
        severity = "high"
    
    strings:
        // Common C&C communication patterns
        $net1 = "http://" ascii wide nocase
        $net2 = "https://" ascii wide nocase
        $net3 = "ftp://" ascii wide nocase
        
        // Suspicious domains/IPs patterns
        $domain1 = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii wide
        $domain2 = ".tk" ascii wide nocase
        $domain3 = ".ml" ascii wide nocase
        $domain4 = ".ga" ascii wide nocase
        
        // Network APIs
        $api1 = "URLDownloadToFile" ascii wide
        $api2 = "InternetOpen" ascii wide
        $api3 = "InternetConnect" ascii wide
        $api4 = "HttpOpenRequest" ascii wide
        $api5 = "send" ascii wide
        $api6 = "recv" ascii wide
        
    condition:
        (1 of ($net*) and 1 of ($domain*) and 2 of ($api*))
}

rule Packed_Executable
{
    meta:
        description = "Detects packed or obfuscated executables"
        author = "Security Team"
        severity = "medium"
    
    strings:
        $mz_header = { 4D 5A }
        
        // Common packers
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
        
        // Other packers
        $aspack = "aPLib" ascii
        $nspack = "NsPack" ascii
        $fsg = "FSG!" ascii
              
    condition:
        $mz_header at 0 and (any of ($upx*) or $aspack or $nspack or $fsg)
}

rule Suspicious_Document_Macros
{
    meta:
        description = "Detects Office documents with suspicious macros"
        author = "Security Team"
        severity = "high"
    
    strings:
        // Office file signatures
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }  // OLE2 signature
        $office2 = { 50 4B 03 04 }              // ZIP signature (newer Office)
        
        // Macro-related strings
        $macro1 = "Auto_Open" ascii wide nocase
        $macro2 = "Document_Open" ascii wide nocase
        $macro3 = "Workbook_Open" ascii wide nocase
        $macro4 = "Auto_Close" ascii wide nocase
        
        // VBA suspicious functions
        $vba1 = "Shell" ascii wide nocase
        $vba2 = "CreateObject" ascii wide nocase
        $vba3 = "GetObject" ascii wide nocase
        $vba4 = "URLDownloadToFile" ascii wide nocase
        $vba5 = "WScript.Shell" ascii wide nocase
        
    condition:
        (1 of ($office*)) and (1 of ($macro*)) and (2 of ($vba*))
}

rule Suspicious_Archive_Content
{
    meta:
        description = "Detects suspicious archive files"
        author = "Security Team"
        severity = "medium"
    
    strings:
        // Archive signatures
        $zip = { 50 4B 03 04 }
        $rar = { 52 61 72 21 1A 07 00 }
        $7z = { 37 7A BC AF 27 1C }
        
        // Suspicious file extensions in archives
        $ext1 = ".exe" ascii wide nocase
        $ext2 = ".scr" ascii wide nocase
        $ext3 = ".pif" ascii wide nocase
        $ext4 = ".com" ascii wide nocase
        $ext5 = ".bat" ascii wide nocase
        $ext6 = ".cmd" ascii wide nocase
        $ext7 = ".vbs" ascii wide nocase
        $ext8 = ".js" ascii wide nocase
        
    condition:
        (1 of ($zip, $rar, $7z)) and (2 of ($ext*))
}

rule Cryptocurrency_Miner
{
    meta:
        description = "Detects potential cryptocurrency mining malware"
        author = "Security Team"
        severity = "medium"
    
    strings:
        // Mining pool addresses
        $pool1 = "stratum+tcp://" ascii wide nocase
        $pool2 = "stratum+ssl://" ascii wide nocase
        
        // Mining software indicators
        $miner1 = "xmrig" ascii wide nocase
        $miner2 = "cpuminer" ascii wide nocase
        $miner3 = "cgminer" ascii wide nocase
        $miner4 = "bfgminer" ascii wide nocase
        
        // Cryptocurrency addresses patterns
        $crypto1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii  // Bitcoin
        $crypto2 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii  // Monero
        
        // Mining configuration
        $config1 = "\"algo\":" ascii wide nocase
        $config2 = "\"pool\":" ascii wide nocase
        $config3 = "\"wallet\":" ascii wide nocase
        
    condition:
        (1 of ($pool*)) or (1 of ($miner*)) or (1 of ($crypto*)) or (2 of ($config*))
}

rule Ransomware_Indicators
{
    meta:
        description = "Detects potential ransomware indicators"
        author = "Security Team"
        severity = "critical"
    
    strings:
        // Ransomware-related strings
        $ransom1 = "encrypted" ascii wide nocase
        $ransom2 = "decrypt" ascii wide nocase
        $ransom3 = "bitcoin" ascii wide nocase
        $ransom4 = "payment" ascii wide nocase
        $ransom5 = "ransom" ascii wide nocase
        
        // File extension changes
        $ext1 = ".locked" ascii wide nocase
        $ext2 = ".encrypted" ascii wide nocase
        $ext3 = ".crypto" ascii wide nocase
        
        // Crypto APIs
        $crypto1 = "CryptEncrypt" ascii wide
        $crypto2 = "CryptDecrypt" ascii wide
        $crypto3 = "CryptGenKey" ascii wide
        
        // File operations
        $file1 = "FindFirstFile" ascii wide
        $file2 = "FindNextFile" ascii wide
        $file3 = "DeleteFile" ascii wide
        
    condition:
        (2 of ($ransom*)) and (1 of ($ext*)) and (1 of ($crypto*)) and (2 of ($file*))
}
