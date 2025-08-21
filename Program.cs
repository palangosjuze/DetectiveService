using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using Microsoft.Win32;
using System.Security.Principal;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.IO;

namespace DetectiveService {
    internal static class Program {

        // where windows keeps service definitions
        private static readonly string REG_PATH = @"SYSTEM\CurrentControlSet\Services";

        private static readonly Regex LuidSuffixRegex = new Regex(@"^(?<base>.+?)_[0-9a-fA-F]{3,}$", RegexOptions.Compiled);

        private static void Main(string[] args) {

            // we need elevated privs to enumerate properly
            if (!IsElevated()) {
                Console.WriteLine("[-] This tool must be run from an elevated console.");
                Environment.Exit(1);
            }

            // scanning and filetering out noise. basically we compare what blue teamer would see using sc query with what we have in the registry
            Console.WriteLine("[*] Scanning registry for per-user *template* services (Type = 0x50 / 0x60)");
            HashSet<string> perUserTemplates = GetPerUserTemplateNames();
            Console.WriteLine($"    → {perUserTemplates.Count} per-user templates detected");

            Console.WriteLine("[*] Grabbing services via sc.. (sc.exe query type= service state= all) …");
            HashSet<string> scm = GetScQueryWin32ServiceNames(perUserTemplates);
            Console.WriteLine($"    → {scm.Count} entries visible via sc.exe");

            Console.WriteLine("[*] Grabbing Win32 service blobs straight from the registry (filtering out drivers and per-user templates)");
            HashSet<string> reg = GetRegistryEntriesSkippingDriversAndUserTemplates();
            Console.WriteLine($"    → {reg.Count} sub-keys considered");

            var hidden = reg.Except(scm, StringComparer.OrdinalIgnoreCase).ToList();

            Console.WriteLine();
            Console.WriteLine("====== POSSIBLE HIDDEN SERVICES ======");

            if (hidden.Count == 0) {

                Console.WriteLine("[+] No shady stuff detected! :)");
                return;
            }

            foreach (string svc in hidden.OrderBy(s => s, StringComparer.OrdinalIgnoreCase)) {

                Console.WriteLine($"[!] You should investigate {svc}");
                PrintServicePathInfo(svc);

                // these are standart service permissions, so if you run this service should be visible with sc query, sc qc commands and etc. You should also be able to stop the service now
                Console.WriteLine("[*] To unhide this service try running:");
                Console.WriteLine($"[*] sc sdset {svc} D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)" +
                                  "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" +
                                  "(A;;CCLCSWLOCRRC;;;IU)" +
                                  "(A;;CCLCSWLOCRRC;;;SU)" +
                                  "S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)");
                Console.WriteLine();
            }
        }

        private static bool IsElevated() {
            using (WindowsIdentity id = WindowsIdentity.GetCurrent()) {

                WindowsPrincipal principal = new WindowsPrincipal(id);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        private static HashSet<string> GetScmEntries() {

            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (ServiceController sc in ServiceController.GetServices())
                set.Add(sc.ServiceName);
            return set;
        }

        private static HashSet<string> GetScQueryWin32ServiceNames(HashSet<string> perUserTemplates) {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try {
                var psi = new ProcessStartInfo { FileName = "sc.exe", Arguments = "query type= service state= all", UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };

                using (Process p = Process.Start(psi)) {
                    if (p == null)
                        throw new InvalidOperationException("Failed to start sc.exe");

                    string output = p.StandardOutput.ReadToEnd();
                    string error = p.StandardError.ReadToEnd();
                    p.WaitForExit();

                    foreach (Match m in Regex.Matches(output, @"SERVICE_NAME:\s+([^\r\n]+)")) {

                        string name = m.Groups[1].Value.Trim();
                        if (!string.IsNullOrWhiteSpace(name))
                            set.Add(name);
                    }

                    if (set.Count == 0 && !string.IsNullOrWhiteSpace(error))
                        Console.WriteLine($"[!] sc.exe returned no services, stderr:\n{error}");
                }
            }
            catch (Exception ex) {
                Console.WriteLine($"[!] Failed to enumerate with sc.exe (falling back to ServiceController): {ex.Message}");
                set = GetScmEntries();
            }

            var toAdd = new List<string>();
            foreach (string name in set) {

                Match m = LuidSuffixRegex.Match(name);
                if (m.Success) {

                    string baseName = m.Groups["base"].Value;
                    if (perUserTemplates.Contains(baseName))
                        toAdd.Add(baseName);
                }
            }

            foreach (string baseName in toAdd)
                set.Add(baseName);

            return set;
        }

        private static HashSet<string> GetPerUserTemplateNames() {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            using (RegistryKey root = Registry.LocalMachine.OpenSubKey(REG_PATH, false)) {
                if (root == null) return set;

                foreach (string sub in root.GetSubKeyNames()) {

                    using (RegistryKey k = root.OpenSubKey(sub, false)) {
                        if (k == null) continue;

                        object typeObj = k.GetValue("Type");
                        if (!(typeObj is int typeVal)) continue;

                        const int SERVICE_USER_OWN_PROCESS = 0x00000050;
                        const int SERVICE_USER_SHARE_PROCESS = 0x00000060;

                        if (typeVal == SERVICE_USER_OWN_PROCESS || typeVal == SERVICE_USER_SHARE_PROCESS)
                            set.Add(sub);
                    }
                }
            }

            return set;
        }

        private static HashSet<string> GetRegistryEntriesSkippingDriversAndUserTemplates() {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            using (RegistryKey root = Registry.LocalMachine.OpenSubKey(REG_PATH, false)) {
                if (root == null) return set;

                foreach (string sub in root.GetSubKeyNames()) {

                    using (RegistryKey k = root.OpenSubKey(sub, false)) {
                        if (k == null) continue;

                        object typeObj = k.GetValue("Type");
                        if (!(typeObj is int typeVal)) continue;

                        const int SERVICE_KERNEL_DRIVER = 0x00000001;
                        const int SERVICE_FILE_SYSTEM_DRIVER = 0x00000002;
                        const int SERVICE_WIN32_OWN_PROCESS = 0x00000010;
                        const int SERVICE_WIN32_SHARE_PROCESS = 0x00000020;
                        const int SERVICE_USER_OWN_PROCESS = 0x00000050;
                        const int SERVICE_USER_SHARE_PROCESS = 0x00000060;

                        bool isDriver = (typeVal & (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER)) != 0;
                        if (isDriver) continue;

                        bool isWin32Like = (typeVal & (SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS)) != 0;
                        if (!isWin32Like) continue;

                        if (typeVal == SERVICE_USER_OWN_PROCESS || typeVal == SERVICE_USER_SHARE_PROCESS)
                            continue;

                        object imagePath = k.GetValue("ImagePath");
                        object serviceDll = null;
                        using (RegistryKey parameters = k.OpenSubKey("Parameters", false)) {
                            if (parameters != null)
                                serviceDll = parameters.GetValue("ServiceDll");
                        }

                        if (imagePath == null && serviceDll == null)
                            continue;

                        if (k.GetValue("DeleteFlag") != null)
                            continue;

                        set.Add(sub);
                    }
                }
            }

            return set;
        }

        private static void PrintServicePathInfo(string serviceName) {
            using (RegistryKey root = Registry.LocalMachine.OpenSubKey(REG_PATH, false)) {
                if (root == null) {

                    Console.WriteLine("    [paths] (registry not accessible)");
                    return;
                }

                using (RegistryKey k = root.OpenSubKey(serviceName, false)) {
                    if (k == null) {

                        Console.WriteLine("    [paths] (service key not found)");
                        return;
                    }

                    object imagePathObj = null;
                    object serviceDllObj = null;

                    try {

                        imagePathObj = k.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    }

                    catch {

                        imagePathObj = k.GetValue("ImagePath");
                    }

                    using (RegistryKey parameters = k.OpenSubKey("Parameters", false)) {

                        if (parameters != null) {

                            try {

                                serviceDllObj = parameters.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                            }

                            catch {

                                serviceDllObj = parameters.GetValue("ServiceDll");
                            }
                        }
                    }

                    string imagePathExpanded = NormalizeAndExpandCommandLine(imagePathObj?.ToString());
                    string serviceDllExpanded = NormalizeAndExpandPath(serviceDllObj?.ToString());

                    string executableFromImagePath = ExtractExecutableFromCommandLine(imagePathExpanded);
                    bool exeExists = !string.IsNullOrWhiteSpace(executableFromImagePath) && File.Exists(executableFromImagePath);
                    bool dllExists = !string.IsNullOrWhiteSpace(serviceDllExpanded) && File.Exists(serviceDllExpanded);

                    if (!string.IsNullOrWhiteSpace(executableFromImagePath))
                        Console.WriteLine("    [bin] " + executableFromImagePath + (exeExists ? " [exists]" : " [missing]"));

                    if (!string.IsNullOrWhiteSpace(imagePathExpanded) && HasArgs(imagePathExpanded))
                        Console.WriteLine("    [cmd] " + imagePathExpanded);

                    if (!string.IsNullOrWhiteSpace(serviceDllExpanded))
                        Console.WriteLine("    [dll] " + serviceDllExpanded + (dllExists ? " [exists]" : " [missing]"));
                }
            }
        }

        private static string NormalizeAndExpandPath(string path) {

            if (string.IsNullOrWhiteSpace(path))
                return null;

            string s = path.Trim();

            try { s = Environment.ExpandEnvironmentVariables(s); } catch { }

            if (s.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(4);
            if (s.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(4);


            string sysRoot = Environment.GetEnvironmentVariable("SystemRoot");
            if (!string.IsNullOrEmpty(sysRoot)) {

                if (s.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                    s = Path.Combine(sysRoot, s.Substring(@"\SystemRoot\".Length));
                else if (s.StartsWith(@"SystemRoot\", StringComparison.OrdinalIgnoreCase))
                    s = Path.Combine(sysRoot, s.Substring(@"SystemRoot\".Length));
            }


            if (s.Length >= 2 && s.StartsWith("\"") && s.EndsWith("\"") && s.Count(c => c == '"') == 2)
                s = s.Substring(1, s.Length - 2);

            string sysDir = Environment.SystemDirectory;
            if (!string.IsNullOrEmpty(sysDir)) {

                if (s.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase) || s.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase)) {

                    s = Path.Combine(sysDir, s.Substring("system32\\".Length));
                }
            }

            return s;
        }

        private static string NormalizeAndExpandCommandLine(string commandLine) {

            if (string.IsNullOrWhiteSpace(commandLine))
                return null;

            string s = commandLine.Trim();

            try { s = Environment.ExpandEnvironmentVariables(s); } catch { }

            if (s.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(4);
            if (s.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(4);

            string sysRoot = Environment.GetEnvironmentVariable("SystemRoot");
            
            if (!string.IsNullOrEmpty(sysRoot)) {

                if (s.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                    s = Path.Combine(sysRoot, s.Substring(@"\SystemRoot\".Length));
                else if (s.StartsWith(@"SystemRoot\", StringComparison.OrdinalIgnoreCase))
                    s = Path.Combine(sysRoot, s.Substring(@"SystemRoot\".Length));
            }

            string sysDir = Environment.SystemDirectory;
            
            if (!string.IsNullOrEmpty(sysDir)) {

                if (s.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase) || s.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase)) {

                    s = Path.Combine(sysDir, s.Substring("system32\\".Length));
                }
            }

            return s;
        }

        private static string ExtractExecutableFromCommandLine(string commandLine) {

            if (string.IsNullOrWhiteSpace(commandLine))
                return null;

            string cl = commandLine.Trim();

            if (cl.StartsWith("\"")) {

                int endQuote = cl.IndexOf('"', 1);
                if (endQuote > 1)
                    return cl.Substring(1, endQuote - 1);
            }

            int spaceIdx = cl.IndexOfAny(new[] { ' ', '\t' });
            
            if (spaceIdx > 0)
                return cl.Substring(0, spaceIdx);

            return cl;
        }

        private static bool HasArgs(string commandLine) {

            if (string.IsNullOrWhiteSpace(commandLine))
                return false;

            string cl = commandLine.Trim();

            if (cl.StartsWith("\"")) {

                int endQuote = cl.IndexOf('"', 1);
                
                if (endQuote > 1) {

                    if (cl.Length > endQuote + 1)
                        return !string.IsNullOrWhiteSpace(cl.Substring(endQuote + 1));
                    return false;
                }
                return false;
            }

            else {

                int spaceIdx = cl.IndexOfAny(new[] { ' ', '\t' });
                if (spaceIdx > 0)
                    return cl.Length > spaceIdx + 1 && !string.IsNullOrWhiteSpace(cl.Substring(spaceIdx + 1));
                return false;
            }


        }
    }
}
