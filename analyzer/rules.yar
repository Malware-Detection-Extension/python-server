rule Malware
{
    strings:
        $malicious_string = "evil_payload"
    condition:
        $malicious_string
}
