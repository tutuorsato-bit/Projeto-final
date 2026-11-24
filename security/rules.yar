rule Suspicious_PowerShell_Download_Pattern
{
    meta:
        description = "Flags archives containing common encoded PowerShell download patterns"
    strings:
        $download = "DownloadString(" nocase
        $encoded = "-EncodedCommand" nocase
        $iex = "IEX(" nocase
    condition:
        2 of them
}
