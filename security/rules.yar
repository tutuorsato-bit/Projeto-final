rule Suspicious_PowerShell_Download_And_Execution
{
    meta:
        description = "Detects PowerShell command patterns that combine remote retrieval with execution"
        category = "suspicious_script_behavior"
        confidence = "medium"
    strings:
        $shell_powershell = "powershell" nocase
        $shell_pwsh = "pwsh" nocase
        $download_string = "DownloadString(" nocase
        $download_file = "DownloadFile(" nocase
        $execute_invoke = "Invoke-Expression" nocase
        $execute_iex = "IEX(" nocase
        $encoded_command = "-EncodedCommand" nocase
    condition:
        (1 of ($shell_*) and 1 of ($download_*) and 1 of ($execute_*))
        or (1 of ($shell_*) and $encoded_command and 1 of ($execute_*))
}

rule Suspicious_Java_Runtime_Command_Execution
{
    meta:
        description = "Detects Java classes that combine process creation with shell command execution"
        category = "suspicious_runtime_behavior"
        confidence = "medium"
    strings:
        $process_builder = "java/lang/ProcessBuilder" ascii
        $runtime_exec = "java/lang/Runtime" ascii
        $exec_method = "exec" ascii
        $shell_unix = "/bin/sh" ascii
        $shell_windows = "cmd.exe" ascii nocase
    condition:
        (($process_builder or $runtime_exec) and $exec_method and ($shell_unix or $shell_windows))
}
