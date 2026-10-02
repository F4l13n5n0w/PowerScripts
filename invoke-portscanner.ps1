#requires -Version 5.1
<#
.SYNOPSIS
Scans IP addresses, hostnames, and CIDRs using TCP, UDP, or a Nmap SYN backend.
.DESCRIPTION
Uses Nmap-style arguments. Default: TCP connect, top 1000 TCP ports, 1000 ms
timeout, 64 concurrent probes. TCP and UDP use .NET sockets. SYN requires
Nmap on PATH and privileges for packet capture (Npcap on Windows).
UDP sends an empty datagram: silence means open|filtered, not open.
Only scan targets for which you have authorization.
.EXAMPLE
.\invoke-portscanner.ps1 127.0.0.1 -sT -p 22,80,443 -oA results
.EXAMPLE
.\invoke-portscanner.ps1 -iL targets.txt -sU --top-ports 10 -oJ udp.json
.EXAMPLE
.\invoke-portscanner.ps1 192.0.2.10 -sS -p 1-1024 -oN syn.txt
.NOTES
Use -h for the complete CLI. Outputs use this project's schema, not Nmap XML.
#>

# Deliberately parse $args so Nmap's case-sensitive and double-dash flags work
# in both Windows PowerShell 5.1 and PowerShell 7.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Show-ScannerHelp {
    @'
Usage: .\invoke-portscanner.ps1 <IP|hostname|CIDR> [<target> ...] [options]
  -sT                       TCP connect scan (default)
  -sS                       True SYN scan through Nmap; requires Nmap/privileges
  -sU                       UDP scan; can combine with -sT or -sS
  -sV                       Check open TCP services using the TCP reference and banners
  --no-progress             Suppress scan/service progress bars
  -iL <file>                Targets separated by whitespace/commas; # comments allowed
  -p <ports>                Ports/ranges: 22,80,443,8000-8010; '-' means 1-65535
  --top-ports <10|100|1000>  Most frequent ports per protocol (default: 1000)
  --timeout-ms <number>     Native probe timeout (default: 1000; range: 1-60000)
  --concurrency <number>    Native concurrent probes (default: 64; range: 1-1024)
  --max-targets <number>    Expansion limit (default: 65536; range: 1-1000000)
  -oN <file>                Plain text
  -oJ <file>                JSON
  -oX <file>                XML (PowerShellPortScanner schema)
  -oG <file>                Grepable text, one line per host
  -oA <basename>            All formats: .txt, .json, .xml, .gnmap
  -h, --help                Show this help

Resolves all hostname A/AAAA addresses; deduplicates targets before scanning.
IPv4 CIDRs omit network/broadcast addresses except /31 and /32. IPv6 CIDRs
include every unicast address. Non-network CIDRs are normalized to the network.
No host discovery, comprehensive version fingerprints, retries, or UDP payload database.
Files are UTF-8 and include every scanned port, including closed ones.
Output files must not already exist. Parent directories must exist.
SYN timing is controlled by Nmap; native timeout/concurrency options do not apply.
'@
}

function Test-ScannerUnicast([Net.IPAddress] $Address) {
    -not ($Address.Equals([Net.IPAddress]::Any) -or $Address.Equals([Net.IPAddress]::IPv6Any) -or
        $Address.IsIPv6Multicast -or ($Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and $Address.GetAddressBytes()[0] -ge 224))
}

function Resolve-ScannerTarget([string] $Target, [int] $Maximum = 65536) {
    if ($Target.Contains('/')) {
        $parts = $Target.Split('/')
        $network = $null
        $prefix = 0
        if ($parts.Count -ne 2 -or -not [Net.IPAddress]::TryParse($parts[0], [ref]$network) -or
            $parts[1] -notmatch '^\d{1,3}$' -or -not [int]::TryParse($parts[1], [ref]$prefix)) {
            throw "Invalid CIDR '$Target'. Use an IPv4/IPv6 address and prefix length."
        }
        $ipv4 = $network.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
        $width = if ($ipv4) { 32 } else { 128 }
        if ($prefix -lt 0 -or $prefix -gt $width) { throw "Invalid CIDR prefix in '$Target': expected 0-$width." }
        $hostBits = $width - $prefix
        # Bound expansion before allocating/enumerating; even IPv6 /0 is cheap
        # to reject. The configurable maximum is at most one million targets.
        if ($hostBits -gt 20) { throw "CIDR '$Target' exceeds --max-targets $Maximum. Use a smaller subnet." }
        $count = [long][Math]::Pow(2, $hostBits)
        $omitEndpoints = $ipv4 -and $prefix -le 30
        $candidateCount = $count
        if ($omitEndpoints) { $candidateCount -= 2 }
        if ($candidateCount -gt $Maximum) { throw "CIDR '$Target' exceeds --max-targets $Maximum. Use a smaller subnet or raise the limit." }
        [byte[]]$bytes = $network.GetAddressBytes()
        for ($index = 0; $index -lt $bytes.Length; $index++) {
            $bits = [Math]::Min(8, [Math]::Max(0, $prefix - 8 * $index))
            $mask = if ($bits -eq 0) { 0 } else { (255 -shl (8 - $bits)) -band 255 }
            $bytes[$index] = [byte]($bytes[$index] -band $mask)
        }
        for ($offset = 0L; $offset -lt $count; $offset++) {
            if (-not ($omitEndpoints -and ($offset -eq 0 -or $offset -eq $count - 1))) {
                $ip = if ($ipv4) { [Net.IPAddress]::new($bytes) } else { [Net.IPAddress]::new($bytes, $network.ScopeId) }
                if (Test-ScannerUnicast $ip) { $ip }
            }
            # Increment the byte array in network order, without signed integer
            # conversions or precision loss on IPv6 addresses.
            for ($index = $bytes.Length - 1; $index -ge 0; $index--) {
                if ($bytes[$index] -lt 255) { $bytes[$index]++; break }
                $bytes[$index] = 0
            }
        }
        return
    }
    $literal = $null
    if ([Net.IPAddress]::TryParse($Target, [ref]$literal)) {
        if (-not (Test-ScannerUnicast $literal)) { throw "Target '$Target' must be a unicast IP address." }
        $literal
        return
    }
    if ([Uri]::CheckHostName($Target) -ne [UriHostNameType]::Dns -or $Target -match '^[\d.]+$') {
        throw "Invalid target '$Target'. Supply an IP address, hostname, or CIDR."
    }
    try { $resolved = @([Net.Dns]::GetHostAddresses($Target)) } catch {
        throw "Cannot resolve hostname '$Target': $($_.Exception.GetBaseException().Message)"
    }
    $unicast = @($resolved | Where-Object { Test-ScannerUnicast $_ })
    if ($unicast.Count -eq 0) { throw "Hostname '$Target' resolved to no unicast IP addresses." }
    $unicast
}

function Expand-PortList([string] $Specification) {
    $set = [Collections.Generic.HashSet[int]]::new()
    if ($Specification -eq '-') { $Specification = '1-65535' }
    foreach ($part in $Specification.Split(',')) {
        if ($part.Trim() -notmatch '^(\d{1,5})(?:-(\d{1,5}))?$') {
            throw "Invalid port specification: '$part'. Use numbers or ranges."
        }
        $first = [int]$Matches[1]
        $last = $first
        if ($Matches[2]) { $last = [int]$Matches[2] }
        if ($first -lt 1 -or $last -gt 65535 -or $first -gt $last) {
            throw "Invalid port range: '$part'. Ports must be 1-65535."
        }
        for ($port = $first; $port -le $last; $port++) { [void]$set.Add($port) }
    }
    @($set | Sort-Object)
}

function New-PortResult($Address, $Port, $Protocol, $Scan, $State, $Reason, $Elapsed) {
    [pscustomobject][ordered]@{
        address = $Address; port = [int]$Port; protocol = $Protocol
        scan = $Scan; state = $State; reason = $Reason; elapsedMs = $Elapsed
        service = $null; serviceSource = $null; version = $null; banner = $null
        serviceCheckReason = $null
    }
}

function Read-ScannerServices([string] $Path) {
    $table = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        # The supplied .csv is a headerless, whitespace-separated Nmap-style
        # table: name, port/tcp, frequency, optional # description.
        if ($line -match '^\s*([^#\s]+)\s+(\d{1,5})/tcp(?:\s|$)') {
            $port = [int]$Matches[2]
            if ($port -ge 1 -and $port -le 65535 -and -not $table.ContainsKey($port)) {
                $table[$port] = $Matches[1]
            }
        }
    }
    if ($table.Count -eq 0) { throw "No TCP service mappings found in '$Path'." }
    $table
}

function Show-ScannerProgress([string] $Phase, [double] $Done, [double] $Total, [string] $Operation) {
    if ($showProgress) {
        $percent = if ($Total -gt 0) { [int][Math]::Min(100, [Math]::Floor(100 * $Done / $Total)) } else { 100 }
        Write-Progress -Id 1 -Activity $Phase -Status "$([long]$Done) / $([long]$Total) completed ($percent%)" -PercentComplete $percent -CurrentOperation $Operation
    }
}

$targetTokens = [Collections.Generic.List[string]]::new()
$scanTypes = [Collections.Generic.List[string]]::new()
$outputFiles = @{}
$portSpec = $null
$topCount = 1000
$topSpecified = $false
$timeoutMs = 1000
$concurrency = 64
$maxTargets = 65536
$serviceCheck = $false
$showProgress = $true
$cli = @($args)
for ($i = 0; $i -lt $cli.Count; $i++) {
    $token = [string]$cli[$i]
    if ($token -ceq '-h' -or $token -ceq '--help') { Show-ScannerHelp; return }
    if ($token -ceq '-sV') { $serviceCheck = $true; continue }
    if ($token -ceq '--no-progress') { $showProgress = $false; continue }
    if ($token -cin @('-sT', '-sS', '-sU')) {
        if (-not $scanTypes.Contains($token)) { $scanTypes.Add($token) }
        continue
    }
    if ($token -cin @('-iL', '-p', '--top-ports', '--timeout-ms', '--concurrency', '--max-targets', '-oN', '-oJ', '-oX', '-oG', '-oA')) {
        if (++$i -ge $cli.Count) { throw "Missing value for $token." }
        # PowerShell may supply an unquoted comma list as a single array argument.
        $value = @($cli[$i]) -join ','
        if ([string]::IsNullOrWhiteSpace($value)) { throw "Empty value for $token." }
        switch -CaseSensitive ($token) {
            '-iL' {
                foreach ($line in Get-Content -LiteralPath $value) {
                    $content = ($line -split '#', 2)[0]
                    foreach ($item in ($content -split '[\s,]+')) {
                        if ($item) { $targetTokens.Add($item) }
                    }
                }
            }
            '-p' { $portSpec = $value }
            '--top-ports' {
                if ($value -notin @('10', '100', '1000')) { throw '--top-ports must be 10, 100, or 1000.' }
                $topCount = [int]$value; $topSpecified = $true
            }
            '--timeout-ms' {
                $number = 0
                if (-not [int]::TryParse($value, [ref]$number) -or $number -lt 1 -or $number -gt 60000) { throw '--timeout-ms must be 1-60000.' }
                $timeoutMs = $number
            }
            '--concurrency' {
                $number = 0
                if (-not [int]::TryParse($value, [ref]$number) -or $number -lt 1 -or $number -gt 1024) { throw '--concurrency must be 1-1024.' }
                $concurrency = $number
            }
            '--max-targets' {
                $number = 0
                if (-not [int]::TryParse($value, [ref]$number) -or $number -lt 1 -or $number -gt 1000000) { throw '--max-targets must be 1-1000000.' }
                $maxTargets = $number
            }
            '-oA' {
                foreach ($entry in @{ N = '.txt'; J = '.json'; X = '.xml'; G = '.gnmap' }.GetEnumerator()) {
                    if ($outputFiles.ContainsKey($entry.Key)) { throw "Output format $($entry.Key) specified twice." }
                    $outputFiles[$entry.Key] = $value + $entry.Value
                }
            }
            default {
                $key = $token.Substring(2)
                if ($outputFiles.ContainsKey($key)) { throw "Output format $key specified twice." }
                $outputFiles[$key] = $value
            }
        }
        continue
    }
    foreach ($item in @($cli[$i])) {
        foreach ($target in ([string]$item -split '[\s,]+')) {
            if ($target.StartsWith('-')) { throw "Unknown option '$target'. Use -h for help (flags are case-sensitive)." }
            if ($target) { $targetTokens.Add($target) }
        }
    }
}
if ($targetTokens.Count -eq 0) { throw 'Supply at least one IP address, hostname, CIDR, or -iL file. Use -h for help.' }
if ($portSpec -and $topSpecified) { throw 'Choose -p or --top-ports, not both.' }
if ($scanTypes.Count -eq 0) { $scanTypes.Add('-sT') }
if ($scanTypes.Contains('-sT') -and $scanTypes.Contains('-sS')) { throw '-sT and -sS are mutually exclusive. Either can be combined with -sU.' }

$addresses = [Collections.Generic.List[string]]::new()
$addressSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$tokenSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($target in $targetTokens) {
    if (-not $tokenSet.Add($target)) { continue }
    foreach ($ip in @(Resolve-ScannerTarget $target $maxTargets)) {
        if ($addressSet.Add($ip.ToString())) {
            if ($addresses.Count -ge $maxTargets) { throw "Resolved targets exceed --max-targets $maxTargets. Narrow the targets or raise the limit." }
            $addresses.Add($ip.ToString())
        }
    }
}
if ($addresses.Count -eq 0) { throw 'Targets contain no scannable unicast addresses.' }

# Validate all output destinations before generating traffic. Never overwrite files.
$destinations = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($key in @($outputFiles.Keys)) {
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($outputFiles[$key])
    if (-not $destinations.Add($full)) { throw 'Output formats must use different paths.' }
    if (Test-Path -LiteralPath $full) { throw "Output already exists: $full" }
    if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($full)) -PathType Container)) { throw "Output directory does not exist: $full" }
    $outputFiles[$key] = $full
}

$portsByProtocol = @{}
if ($portSpec) {
    $selected = @(Expand-PortList $portSpec)
    $portsByProtocol.tcp = $selected; $portsByProtocol.udp = $selected
} else {
    $rankings = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'data\top-ports.json') -Raw | ConvertFrom-Json
    $portsByProtocol.tcp = @($rankings.tcp | Select-Object -First $topCount)
    $portsByProtocol.udp = @($rankings.udp | Select-Object -First $topCount)
    if ($portsByProtocol.tcp.Count -ne $topCount -or $portsByProtocol.udp.Count -ne $topCount) { throw 'Port ranking data is incomplete.' }
}
$nmap = $null
if ($scanTypes.Contains('-sS')) {
    $nmap = Get-Command nmap -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $nmap) { throw '-sS requires Nmap on PATH, Npcap on Windows, and SYN scan privileges. Use -sT for native TCP connect scanning.' }
}
$serviceTable = @{}
if ($serviceCheck) {
    $servicePath = Join-Path $PSScriptRoot 'services_tcp.csv'
    # Accept the spelling from the request too, without renaming user data.
    if (-not (Test-Path -LiteralPath $servicePath -PathType Leaf)) { $servicePath = Join-Path $PSScriptRoot 'servivces_tcp.csv' }
    $serviceTable = Read-ScannerServices $servicePath
}

# Native async workers avoid PowerShell runspace overhead and keep outstanding
# sockets bounded. No PowerShell callbacks run on worker threads.
if (-not ('PowerShellPortScannerV2.NativeScanner' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using System.Text.RegularExpressions;
namespace PowerShellPortScannerV2 {
    public sealed class Progress {
        private int completed;
        public int Completed { get { return Volatile.Read(ref completed); } }
        public void Complete() { Interlocked.Increment(ref completed); }
    }
    public sealed class Service {
        public string Name;
        public string Source;
        public string Version;
        public string Banner;
        public string Reason;
    }
    public sealed class Probe {
        public int Port;
        public string State;
        public string Reason;
        public long ElapsedMs;
    }
    public static class NativeScanner {
        private static async Task<Probe> One(IPAddress ip, int port, bool udp, int timeout) {
            var clock = Stopwatch.StartNew();
            var result = new Probe { Port = port };
            using (var socket = new Socket(ip.AddressFamily, udp ? SocketType.Dgram : SocketType.Stream,
                udp ? ProtocolType.Udp : ProtocolType.Tcp)) {
                try {
                    var endpoint = new IPEndPoint(ip, port);
                    Task operation;
                    if (udp) {
                        socket.Connect(endpoint);
                        socket.Send(new byte[0]);
                        var receive = new SocketAsyncEventArgs();
                        receive.SetBuffer(new byte[65535], 0, 65535);
                        var completion = new TaskCompletionSource<bool>();
                        receive.Completed += (sender, e) => {
                            if (e.SocketError == SocketError.Success) completion.TrySetResult(true);
                            else completion.TrySetException(new SocketException((int)e.SocketError));
                        };
                        try {
                            if (!socket.ReceiveAsync(receive)) {
                                if (receive.SocketError == SocketError.Success) completion.TrySetResult(true);
                                else completion.TrySetException(new SocketException((int)receive.SocketError));
                            }
                            operation = completion.Task;
                            if (await Task.WhenAny(operation, Task.Delay(timeout)).ConfigureAwait(false) != operation) {
                                socket.Close();
                                try { await operation.ConfigureAwait(false); } catch (SocketException) { }
                                result.State = "open|filtered"; result.Reason = "no-response";
                            } else {
                                await operation.ConfigureAwait(false);
                                result.State = "open"; result.Reason = "udp-response";
                            }
                        } finally { receive.Dispose(); }
                    } else {
                        operation = Task.Factory.FromAsync(socket.BeginConnect, socket.EndConnect, endpoint, null);
                        if (await Task.WhenAny(operation, Task.Delay(timeout)).ConfigureAwait(false) != operation) {
                            socket.Close();
                            try { await operation.ConfigureAwait(false); } catch (SocketException) { } catch (ObjectDisposedException) { }
                            result.State = "filtered"; result.Reason = "connect-timeout";
                        } else {
                            await operation.ConfigureAwait(false);
                            result.State = "open"; result.Reason = "connection-established";
                        }
                    }
                } catch (SocketException e) {
                    result.Reason = e.SocketErrorCode.ToString();
                    if (e.SocketErrorCode == SocketError.ConnectionRefused || (udp && e.SocketErrorCode == SocketError.ConnectionReset)) result.State = "closed";
                    else if (e.SocketErrorCode == SocketError.TimedOut) result.State = udp ? "open|filtered" : "filtered";
                    else if (e.SocketErrorCode == SocketError.HostUnreachable || e.SocketErrorCode == SocketError.NetworkUnreachable) result.State = "filtered";
                    else result.State = "error";
                }
            }
            result.ElapsedMs = clock.ElapsedMilliseconds;
            return result;
        }
        public static async Task<Probe[]> Scan(string address, int[] ports, bool udp, int timeout, int concurrency, Progress progress) {
            var ip = IPAddress.Parse(address);
            var results = new Probe[ports.Length];
            int cursor = -1;
            var workers = new List<Task>();
            for (int w = 0; w < Math.Min(concurrency, ports.Length); w++) {
                workers.Add(Task.Run(async () => {
                    int index;
                    while ((index = Interlocked.Increment(ref cursor)) < ports.Length) {
                        results[index] = await One(ip, ports[index], udp, timeout).ConfigureAwait(false);
                        progress.Complete();
                    }
                }));
            }
            await Task.WhenAll(workers).ConfigureAwait(false);
            return results;
        }
        private static async Task<Service> CheckService(string address, int port, string reference, int timeout) {
            var result = new Service { Name = reference, Source = reference == "unknown" ? "unknown" : "port-table", Reason = "no-banner" };
            using (var client = new TcpClient(IPAddress.Parse(address).AddressFamily)) {
                try {
                    var connect = client.ConnectAsync(IPAddress.Parse(address), port);
                    if (await Task.WhenAny(connect, Task.Delay(timeout)).ConfigureAwait(false) != connect) {
                        client.Close();
                        try { await connect.ConfigureAwait(false); } catch (Exception) { }
                        result.Reason = "connect-timeout"; return result;
                    }
                    await connect.ConfigureAwait(false);
                    var stream = client.GetStream();
                    // No arbitrary payloads: only a read-only HEAD request to
                    // mapped plaintext HTTP services; other protocols are passive.
                    if (reference == "http" || reference == "http-alt" || reference == "http-proxy") {
                        string host = address.IndexOf(':') >= 0 ? "[" + address + "]" : address;
                        byte[] request = Encoding.ASCII.GetBytes("HEAD / HTTP/1.0\r\nHost: " + host + ":" + port + "\r\nConnection: close\r\n\r\n");
                        var write = stream.WriteAsync(request, 0, request.Length);
                        if (await Task.WhenAny(write, Task.Delay(timeout)).ConfigureAwait(false) != write) {
                            client.Close(); try { await write.ConfigureAwait(false); } catch (Exception) { }
                            result.Reason = "write-timeout"; return result;
                        }
                        await write.ConfigureAwait(false);
                    }
                    var bytes = new byte[4096];
                    int used = 0;
                    var clock = Stopwatch.StartNew();
                    while (used < bytes.Length && clock.ElapsedMilliseconds < timeout) {
                        var read = stream.ReadAsync(bytes, used, bytes.Length - used);
                        int remaining = Math.Max(1, timeout - (int)clock.ElapsedMilliseconds);
                        if (await Task.WhenAny(read, Task.Delay(remaining)).ConfigureAwait(false) != read) {
                            client.Close(); try { await read.ConfigureAwait(false); } catch (Exception) { }
                            break;
                        }
                        int received = await read.ConfigureAwait(false);
                        if (received == 0) break;
                        used += received;
                        string partial = Encoding.ASCII.GetString(bytes, 0, used);
                        bool http = partial.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase);
                        if ((http && partial.Contains("\r\n\r\n")) || (!http && partial.Contains("\n"))) break;
                    }
                    if (used == 0) return result;
                    string raw = Encoding.ASCII.GetString(bytes, 0, used);
                    // Escape control characters before console/export display.
                    result.Banner = Regex.Replace(raw, "[^\\x20-\\x7e]", m => "\\x" + ((int)m.Value[0]).ToString("X2"));
                    result.Reason = "banner-received";
                    Match match;
                    if ((match = Regex.Match(raw, @"^SSH-\d+\.\d+-([^\r\n]+)")).Success) {
                        result.Name = "ssh"; result.Version = match.Groups[1].Value.Trim(); result.Source = "banner";
                    } else if (Regex.IsMatch(raw, @"^HTTP/\d(?:\.\d)? \d{3}")) {
                        result.Name = "http"; result.Source = "banner";
                        match = Regex.Match(raw, @"(?im)^Server:\s*([^\r\n]+)");
                        if (match.Success) result.Version = match.Groups[1].Value.Trim();
                    } else if (Regex.IsMatch(raw, @"^220[ -].*\b(?:ESMTP|SMTP)\b", RegexOptions.IgnoreCase)) {
                        result.Name = "smtp"; result.Source = "banner";
                    } else if (Regex.IsMatch(raw, @"^220[ -].*\bFTP\b", RegexOptions.IgnoreCase)) {
                        result.Name = "ftp"; result.Source = "banner";
                    } else if (Regex.IsMatch(raw, @"^\+OK.*\bPOP3?\b", RegexOptions.IgnoreCase)) {
                        result.Name = "pop3"; result.Source = "banner";
                    } else if (Regex.IsMatch(raw, @"^\* OK.*\bIMAP", RegexOptions.IgnoreCase)) {
                        result.Name = "imap"; result.Source = "banner";
                    }
                    if (result.Version != null) result.Version = Regex.Replace(result.Version, "[^\\x20-\\x7e]", m => "\\x" + ((int)m.Value[0]).ToString("X2"));
                } catch (SocketException e) { result.Reason = e.SocketErrorCode.ToString(); }
                  catch (System.IO.IOException) { result.Reason = "io-error"; }
                  catch (ObjectDisposedException) { result.Reason = "connection-closed"; }
            }
            return result;
        }
        public static async Task<Service[]> Services(string[] addresses, int[] ports, string[] references, int timeout, int concurrency, Progress progress) {
            var results = new Service[ports.Length];
            int cursor = -1;
            var workers = new List<Task>();
            for (int w = 0; w < Math.Min(concurrency, ports.Length); w++) {
                workers.Add(Task.Run(async () => {
                    int index;
                    while ((index = Interlocked.Increment(ref cursor)) < ports.Length) {
                        results[index] = await CheckService(addresses[index], ports[index], references[index], timeout).ConfigureAwait(false);
                        progress.Complete();
                    }
                }));
            }
            await Task.WhenAll(workers).ConfigureAwait(false);
            return results;
        }
    }
}
'@
}

$started = [DateTime]::UtcNow
$results = [Collections.Generic.List[object]]::new()
$totalProbes = 0L
foreach ($scan in $scanTypes) {
    $protocol = if ($scan -ceq '-sU') { 'udp' } else { 'tcp' }
    $totalProbes += [long]$addresses.Count * $portsByProtocol[$protocol].Count
}
$completedProbes = 0L
try {
foreach ($address in $addresses) {
    foreach ($scan in $scanTypes) {
        $protocol = if ($scan -ceq '-sU') { 'udp' } else { 'tcp' }
        $ports = [int[]]$portsByProtocol[$protocol]
        Write-Host "Scanning $address $scan ($($ports.Count) $protocol ports)..."
        Show-ScannerProgress 'Port scanning' $completedProbes $totalProbes "$address $scan"
        if ($scan -cne '-sS') {
            $progress = [PowerShellPortScannerV2.Progress]::new()
            $task = [PowerShellPortScannerV2.NativeScanner]::Scan($address, $ports, ($protocol -eq 'udp'), $timeoutMs, $concurrency, $progress)
            while (-not $task.IsCompleted) {
                Show-ScannerProgress 'Port scanning' ($completedProbes + $progress.Completed) $totalProbes "$address $scan"
                Start-Sleep -Milliseconds 100
            }
            foreach ($probe in $task.GetAwaiter().GetResult()) {
                $results.Add((New-PortResult $address $probe.Port $protocol $scan $probe.State $probe.Reason $probe.ElapsedMs))
            }
        } else {
            $tempXml = [IO.Path]::GetTempFileName()
            try {
                $nmapArgs = @('-sS', '-Pn', '-n', '--reason', '--stats-every', '1s', '-p', ($ports -join ','), '-oX', $tempXml)
                if ([Net.IPAddress]::Parse($address).AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $nmapArgs += '-6' }
                $nmapArgs += $address
                # Windows PowerShell turns native stderr into ErrorRecords;
                # collect warnings and rely on the native exit code for failure.
                $savedPreference = $ErrorActionPreference
                try {
                    $ErrorActionPreference = 'Continue'
                    $nativeOutput = & $nmap.Source @nmapArgs 2>&1 | ForEach-Object {
                        if ([string]$_ -match 'About\s+([0-9.]+)%\s+done') {
                            $fraction = [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture) / 100
                            Show-ScannerProgress 'Port scanning (SYN estimate)' ($completedProbes + $ports.Count * $fraction) $totalProbes "$address $scan"
                        }
                        $_
                    }
                    $nativeExit = $LASTEXITCODE
                } finally { $ErrorActionPreference = $savedPreference }
                if ($nativeExit -ne 0) { throw "Nmap SYN scan failed (exit $nativeExit): $($nativeOutput -join [Environment]::NewLine)" }
                $document = [Xml.XmlDocument]::new()
                $document.XmlResolver = $null
                try { $document.Load($tempXml) } catch {
                    throw "Nmap returned invalid XML: $($_.Exception.Message) Backend output: $($nativeOutput -join [Environment]::NewLine)"
                }
                if (l) { throw 'Nmap did not confirm a SYN scan.' }
                $hostNode = $document.SelectSingleNode('/nmaprun/host')
                if ($null -eq $hostNode) { throw "Nmap returned no host results for $address." }
                $explicit = @{}
                foreach ($node in $hostNode.SelectNodes('ports/port')) { $explicit[[int]$node.GetAttribute('portid')] = $node }
                $extra = @($hostNode.SelectNodes('ports/extraports'))
                foreach ($port in $ports) {
                    if ($explicit.ContainsKey($port)) {
                        $node = $explicit[$port].SelectSingleNode('state')
                        $state = $node.GetAttribute('state'); $reason = $node.GetAttribute('reason')
                    } elseif ($extra.Count -eq 1) {
                        $state = $extra[0].GetAttribute('state'); $reason = 'nmap-extraports'
                    } else {
                        $state = 'unknown'; $reason = 'nmap-aggregated-states'
                        foreach ($group in $extra) {
                            foreach ($reasonNode in $group.SelectNodes('extrareasons[@ports]')) {
                                if ($port -in @(Expand-PortList $reasonNode.GetAttribute('ports'))) {
                                    $state = $group.GetAttribute('state'); $reason = $reasonNode.GetAttribute('reason')
                                }
                            }
                        }
                    }
                    $results.Add((New-PortResult $address $port 'tcp' $scan $state $reason $null))
                }
            } finally { Remove-Item -LiteralPath $tempXml -ErrorAction SilentlyContinue }
        }
        $completedProbes += $ports.Count
        Show-ScannerProgress 'Port scanning' $completedProbes $totalProbes "$address $scan"
    }
}
if ($serviceCheck) {
    $openTcp = @($results | Where-Object { $_.protocol -eq 'tcp' -and $_.state -eq 'open' })
    if ($openTcp.Count -gt 0) {
        Write-Host "Checking $($openTcp.Count) open TCP services..."
        $references = [string[]]@($openTcp | ForEach-Object {
            if ($serviceTable.ContainsKey($_.port)) { $serviceTable[$_.port] } else { 'unknown' }
        })
        $progress = [PowerShellPortScannerV2.Progress]::new()
        # Array.Address is a .NET method; enumerate the address property
        # explicitly rather than using member enumeration on the array.
        $serviceAddresses = [string[]]@($openTcp | ForEach-Object { $_.address })
        $servicePorts = [int[]]@($openTcp | ForEach-Object { $_.port })
        $task = [PowerShellPortScannerV2.NativeScanner]::Services($serviceAddresses, $servicePorts, $references, $timeoutMs, $concurrency, $progress)
        while (-not $task.IsCompleted) {
            Show-ScannerProgress 'Checking TCP services' $progress.Completed $openTcp.Count 'Reading banners / checking mapped HTTP services'
            Start-Sleep -Milliseconds 100
        }
        $services = $task.GetAwaiter().GetResult()
        for ($index = 0; $index -lt $openTcp.Count; $index++) {
            $openTcp[$index].service = $services[$index].Name
            $openTcp[$index].serviceSource = $services[$index].Source
            $openTcp[$index].version = $services[$index].Version
            $openTcp[$index].banner = $services[$index].Banner
            $openTcp[$index].serviceCheckReason = $services[$index].Reason
        }
        Show-ScannerProgress 'Checking TCP services' $openTcp.Count $openTcp.Count 'Complete'
    }
}
} finally { if ($showProgress) { Write-Progress -Id 1 -Activity 'Port scanner' -Completed } }
$report = [pscustomobject][ordered]@{
    scanner = 'PowerShellPortScanner'; schemaVersion = 1
    startedUtc = $started.ToString('o'); finishedUtc = [DateTime]::UtcNow.ToString('o')
    targets = @($addresses.ToArray()); scans = @($scanTypes.ToArray())
    requestedTargets = @($targetTokens.ToArray())
    serviceCheck = $serviceCheck
    portSelection = if ($portSpec) { $portSpec } else { "top-$topCount" }
    timeoutMs = $timeoutMs; concurrency = $concurrency
    results = @($results.ToArray())
}
$textLines = [Collections.Generic.List[string]]::new()
$textLines.Add("PowerShellPortScanner $($report.startedUtc)")
$textLines.Add("Address`tPort/Protocol`tScan`tState`tReason`tElapsedMs`tService`tServiceSource`tVersion`tBanner`tServiceCheckReason")
foreach ($result in $results) {
    $textLines.Add("$($result.address)`t$($result.port)/$($result.protocol)`t$($result.scan)`t$($result.state)`t$($result.reason)`t$($result.elapsedMs)`t$($result.service)`t$($result.serviceSource)`t$($result.version)`t$($result.banner)`t$($result.serviceCheckReason)")
}
$textLines.Add("Finished: $($report.finishedUtc)")
$grepLines = [Collections.Generic.List[string]]::new()
$grepLines.Add("# PowerShellPortScanner $($report.startedUtc)")
foreach ($address in $addresses) {
    $entries = @($results | Where-Object address -EQ $address | ForEach-Object {
        $service = ([string]$_.service).Replace('/', '|').Replace(',', ';')
        $version = ([string]$_.version).Replace('/', '|').Replace(',', ';')
        "$($_.port)/$($_.state)/$($_.protocol)//$service//$version/"
    })
    $grepLines.Add("Host: $address ()`tPorts: $($entries -join ', ')")
}
$utf8 = [Text.UTF8Encoding]::new($false)
foreach ($key in $outputFiles.Keys) {
    $content = switch ($key) {
        'N' { $textLines -join [Environment]::NewLine }
        'J' { $report | ConvertTo-Json -Depth 8 }
        'G' { $grepLines -join [Environment]::NewLine }
        'X' {
            $builder = [Text.StringBuilder]::new()
            $settings = [Xml.XmlWriterSettings]::new(); $settings.Indent = $true; $settings.OmitXmlDeclaration = $true
            $writer = [Xml.XmlWriter]::Create($builder, $settings)
            try {
                $writer.WriteStartElement('PowerShellPortScanner')
                $writer.WriteAttributeString('schemaVersion', '1')
                $writer.WriteAttributeString('startedUtc', $report.startedUtc)
                $writer.WriteAttributeString('finishedUtc', $report.finishedUtc)
                foreach ($address in $addresses) {
                    $writer.WriteStartElement('host'); $writer.WriteAttributeString('address', $address)
                    foreach ($result in @($results | Where-Object address -EQ $address)) {
                        $writer.WriteStartElement('port')
                        foreach ($field in @('port', 'protocol', 'scan', 'state', 'reason', 'elapsedMs', 'service', 'serviceSource', 'version', 'banner', 'serviceCheckReason')) {
                            $writer.WriteAttributeString($field, [string]$result.$field)
                        }
                        $writer.WriteEndElement()
                    }
                    $writer.WriteEndElement()
                }
                $writer.WriteEndElement(); $writer.Flush()
                $builder.ToString()
            } finally { $writer.Dispose() }
        }
    }
    # CreateNew prevents a race from overwriting a file created during scanning.
    $stream = [IO.File]::Open($outputFiles[$key], [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try {
        $bytes = $utf8.GetBytes($content + [Environment]::NewLine)
        $stream.Write($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
    Write-Host "Saved $($outputFiles[$key])"
}
$visible = @($results | Where-Object { $_.state -in @('open', 'open|filtered', 'error', 'unknown') })
if ($visible.Count) {
    if ($serviceCheck) { $visible | Format-Table address, port, protocol, state, service, serviceSource, version -AutoSize | Out-Host }
    else { $visible | Format-Table address, port, protocol, state, reason -AutoSize | Out-Host }
}
foreach ($group in ($results | Group-Object state)) { Write-Host "$($group.Name): $($group.Count)" }
# Return structured results for callers, separately from console formatting.
$report
