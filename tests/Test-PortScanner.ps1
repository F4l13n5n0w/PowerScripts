#requires -Version 5.1
# Integration tests use only loopback sockets. No external hosts are scanned.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$scanner = Join-Path (Split-Path $PSScriptRoot -Parent) 'invoke-portscanner.ps1'
$testDirectory = Join-Path ([IO.Path]::GetTempPath()) ('portscanner-tests-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $testDirectory)
function Assert($Condition, [string] $Message) {
    if (-not $Condition) { throw "Assertion failed: $Message" }
}
function Assert-Rejected([scriptblock] $Action, [string] $Expected) {
    $caught = $null
    try { & $Action | Out-Null } catch { $caught = $_.Exception.Message }
    Assert ($null -ne $caught -and $caught -like "*$Expected*") "Expected rejection containing '$Expected', got '$caught'"
}
# Load target helpers without scanning documentation ranges.
. $scanner -h | Out-Null
Assert ((@(Resolve-ScannerTarget '192.0.2.7/30') -join ',') -eq '192.0.2.5,192.0.2.6') 'IPv4 CIDR normalizes and omits network/broadcast'
Assert ((@(Resolve-ScannerTarget '192.0.2.7/31') -join ',') -eq '192.0.2.6,192.0.2.7') 'IPv4 /31 includes both endpoints'
Assert ((@(Resolve-ScannerTarget '192.0.2.7/32') -join ',') -eq '192.0.2.7') 'IPv4 /32 includes one address'
Assert (@(Resolve-ScannerTarget '192.0.2.123/24').Count -eq 254) 'IPv4 /24 expansion'
Assert ((@(Resolve-ScannerTarget '2001:db8::7/126') -join ',') -eq '2001:db8::4,2001:db8::5,2001:db8::6,2001:db8::7') 'IPv6 normalization and expansion'
Assert ((@(Resolve-ScannerTarget '2001:db8::7/127') -join ',') -eq '2001:db8::6,2001:db8::7') 'IPv6 /127'
Assert ((@(Resolve-ScannerTarget '2001:db8::7/128') -join ',') -eq '2001:db8::7') 'IPv6 /128'
Assert (@(Resolve-ScannerTarget '2001:db8::ff/120').Count -eq 256) 'IPv6 byte boundary expansion'
Assert (@(Resolve-ScannerTarget 'localhost').Count -ge 1) 'Local hostname resolution'
Assert-Rejected { Resolve-ScannerTarget '192.0.2.1/33' } 'Invalid CIDR prefix'
Assert-Rejected { Resolve-ScannerTarget '2001:db8::/129' } 'Invalid CIDR prefix'
Assert-Rejected { Resolve-ScannerTarget '192.0.2.1/-1' } 'Invalid CIDR'
Assert-Rejected { Resolve-ScannerTarget 'hostname/24' } 'Invalid CIDR'
Assert-Rejected { Resolve-ScannerTarget '::/0' } 'exceeds --max-targets'
Assert-Rejected { Resolve-ScannerTarget '192.0.2.0/24' 10 } 'exceeds --max-targets'
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
public sealed class ScannerTestUdpEcho : IDisposable {
    private UdpClient server;
    private Task worker;
    public int Port { get; private set; }
    public ScannerTestUdpEcho() {
        server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        Port = ((IPEndPoint)server.Client.LocalEndPoint).Port;
        worker = Task.Run(() => {
            try {
                while (true) {
                    IPEndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                    server.Receive(ref remote);
                    server.Send(new byte[] { 79, 75 }, 2, remote);
                }
            } catch (SocketException) { } catch (ObjectDisposedException) { }
        });
    }
    public void Dispose() { server.Close(); worker.Wait(2000); }
}
public sealed class ScannerTestBanner : IDisposable {
    private TcpListener listener;
    private Task worker;
    public int Port { get; private set; }
    public ScannerTestBanner(bool http) {
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        worker = Task.Run(() => {
            try {
                while (true) {
                    using (var client = listener.AcceptTcpClient()) {
                        try {
                            var stream = client.GetStream();
                            if (http) {
                                client.ReceiveTimeout = 1000;
                                var buffer = new byte[2048];
                                if (stream.Read(buffer, 0, buffer.Length) == 0) continue;
                            }
                            string response = http ? "HTTP/1.0 200 OK\r\nServer: LocalTest/1.2\r\nContent-Length: 0\r\n\r\n" : "SSH-2.0-LocalSSH_1.2\r\n";
                            byte[] bytes = System.Text.Encoding.ASCII.GetBytes(response);
                            stream.Write(bytes, 0, bytes.Length);
                        } catch (System.IO.IOException) { } catch (SocketException) { }
                    }
                }
            } catch (SocketException) { } catch (ObjectDisposedException) { }
        });
    }
    public void Dispose() { listener.Stop(); worker.Wait(3000); }
}
'@
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$echo = $null
$silent = $null
$ssh = $null
$http = $null
try {
    $listener.Start()
    $tcpPort = $listener.LocalEndpoint.Port
    $closedListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $closedListener.Start(); $closedPort = $closedListener.LocalEndpoint.Port; $closedListener.Stop()
    $echo = [ScannerTestUdpEcho]::new()
    $silent = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0))
    $silentPort = $silent.Client.LocalEndPoint.Port

    $base = Join-Path $testDirectory 'results'
    $report = & $scanner 127.0.0.1 -sT -p "$tcpPort,$closedPort" --timeout-ms 3000 -oA $base
    Assert (@($report.results | Where-Object { $_.port -eq $tcpPort -and $_.state -eq 'open' }).Count -eq 1) 'TCP listener is open'
    Assert (@($report.results | Where-Object { $_.port -eq $closedPort -and $_.state -eq 'closed' }).Count -eq 1) 'Unused TCP port is closed'
    $json = Get-Content -LiteralPath "$base.json" -Raw | ConvertFrom-Json
    Assert ($json.results.Count -eq 2) 'JSON includes all ports'
    $xml = [xml](Get-Content -LiteralPath "$base.xml" -Raw)
    Assert ($xml.PowerShellPortScanner.host.port.Count -eq 2) 'XML includes all ports'
    Assert ((Get-Content -LiteralPath "$base.gnmap" -Raw) -match "$tcpPort/open/tcp") 'Grepable output includes open TCP port'
    Assert ((Get-Content -LiteralPath "$base.txt" -Raw) -match "$closedPort/tcp") 'Text includes closed TCP port'
    Assert-Rejected { & $scanner 127.0.0.1 -p $tcpPort -oA $base } 'Output already exists'

    $udp = & $scanner 127.0.0.1 -sU -p "$($echo.Port),$silentPort" --timeout-ms 200
    Assert (@($udp.results | Where-Object { $_.port -eq $echo.Port -and $_.state -eq 'open' }).Count -eq 1) 'UDP reply means open'
    Assert (@($udp.results | Where-Object { $_.port -eq $silentPort -and $_.state -eq 'open|filtered' }).Count -eq 1) 'UDP silence means open|filtered'

    $inputFile = Join-Path $testDirectory 'targets.txt'
    "# test targets`n127.0.0.1, 127.0.0.1 # deduplicate" | Set-Content -LiteralPath $inputFile
    $combined = & $scanner -iL $inputFile -sT -sU -p $tcpPort --timeout-ms 100
    Assert ($combined.targets.Count -eq 1 -and $combined.results.Count -eq 2) 'Input file comments, duplicates, and combined scans'
    $range = & $scanner 127.0.0.1 -p '1-3,2' --timeout-ms 30
    Assert ($range.results.Count -eq 3) 'Ranges deduplicate ports'
    $comma = & $scanner 127.0.0.1,127.0.0.1 -p 1,2 --timeout-ms 30
    Assert ($comma.targets.Count -eq 1 -and $comma.results.Count -eq 2) 'Unquoted PowerShell comma arrays'
    $hostname = & $scanner localhost -p $tcpPort --timeout-ms 100
    Assert (@($hostname.results | Where-Object { $_.address -eq '127.0.0.1' -and $_.state -eq 'open' }).Count -eq 1) 'Hostname scans resolved loopback addresses'
    Assert ($hostname.requestedTargets[0] -eq 'localhost') 'Report preserves requested hostname'
    $subnet = & $scanner 127.0.0.1/30 127.0.0.1 -p 1 --timeout-ms 20
    Assert (($subnet.targets -join ',') -eq '127.0.0.1,127.0.0.2') 'CLI CIDR deduplicates explicit targets'
    "localhost`n127.0.0.1/32 # CIDR in file`n127.0.0.1" | Set-Content -LiteralPath $inputFile
    $mixed = & $scanner -iL $inputFile -p $tcpPort --timeout-ms 100
    Assert (@($mixed.results | Where-Object address -EQ '127.0.0.1').Count -eq 1) 'Hostname, CIDR, and IP in file deduplicate'
    Assert-Rejected { & $scanner 127.0.0.1/30 --max-targets 1 -p 1 } 'exceeds --max-targets'
    Assert-Rejected { & $scanner 127.0.0.1 127.0.0.2 --max-targets 1 -p 1 } 'exceed --max-targets'
    Assert-Rejected { & $scanner 127.0.0.1 --max-targets 0 } '--max-targets must'

    $ssh = [ScannerTestBanner]::new($false)
    $http = [ScannerTestBanner]::new($true)
    $serviceBase = Join-Path $testDirectory 'services'
    $serviceReport = & $scanner 127.0.0.1 -p $ssh.Port -sV -oA $serviceBase --timeout-ms 500 --no-progress
    Assert ($serviceReport.results[0].service -eq 'ssh' -and $serviceReport.results[0].serviceSource -eq 'banner') 'Active service identification on a nonstandard port'
    Assert ($serviceReport.results[0].version -eq 'LocalSSH_1.2') 'SSH version banner'
    $serviceJson = Get-Content -LiteralPath "$serviceBase.json" -Raw | ConvertFrom-Json
    Assert ($serviceJson.results[0].service -eq 'ssh') 'JSON service fields'
    $serviceXml = [xml](Get-Content -LiteralPath "$serviceBase.xml" -Raw)
    Assert ($serviceXml.PowerShellPortScanner.host.port.service -eq 'ssh') 'XML service fields'
    Assert ((Get-Content -LiteralPath "$serviceBase.txt" -Raw) -match 'LocalSSH_1.2') 'Text version export'
    Assert ((Get-Content -LiteralPath "$serviceBase.gnmap" -Raw) -match '/ssh//LocalSSH_1.2/') 'Grepable service/version export'
    $counter = [PowerShellPortScannerV2.Progress]::new()
    $httpTask = [PowerShellPortScannerV2.NativeScanner]::Services(@('127.0.0.1'), @($http.Port), @('http'), 500, 1, $counter)
    $httpService = $httpTask.GetAwaiter().GetResult()
    Assert ($httpService[0].Name -eq 'http' -and $httpService[0].Version -eq 'LocalTest/1.2') 'Mapped HTTP HEAD request and Server header'
    Assert ($counter.Completed -eq 1) 'Service progress counter increments'
    $silentService = & $scanner 127.0.0.1 -p $tcpPort -sV --timeout-ms 100 --no-progress
    Assert ($silentService.results[0].serviceCheckReason -eq 'no-banner' -and $silentService.results[0].serviceSource -ne 'banner') 'Silent service preserves hint without claiming confirmation'
    $table = Read-ScannerServices (Join-Path (Split-Path $PSScriptRoot -Parent) 'services_tcp.csv')
    Assert ($table[22] -eq 'ssh' -and $table[80] -eq 'http') 'Headerless tab-separated service reference'
    $counter = [PowerShellPortScannerV2.Progress]::new()
    $nativeTask = [PowerShellPortScannerV2.NativeScanner]::Scan('127.0.0.1', @($ssh.Port, $http.Port), $false, 500, 1, $counter)
    [void]$nativeTask.GetAwaiter().GetResult()
    Assert ($counter.Completed -eq 2) 'Native scan progress counts completed probes'
    $progressEvents = [Collections.Generic.List[object]]::new()
    function Write-Progress {
        param($Id, $Activity, $Status, $PercentComplete, $CurrentOperation, [switch]$Completed)
        $progressEvents.Add([pscustomobject]@{ Percent = $PercentComplete; Done = $Completed.IsPresent })
    }
    try {
        $null = & $scanner 127.0.0.1 -p $ssh.Port
        Assert (@($progressEvents | Where-Object Percent -EQ 100).Count -gt 0) 'Progress bar reaches 100 percent'
        Assert ($progressEvents[$progressEvents.Count - 1].Done) 'Progress bar is cleared'
        $progressEvents.Clear()
        $null = & $scanner 127.0.0.1 -p $ssh.Port --no-progress
        Assert ($progressEvents.Count -eq 0) 'Progress suppression flag'
    } finally { Remove-Item -LiteralPath Function:\Write-Progress }

    $rankings = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'data\top-ports.json') -Raw | ConvertFrom-Json
    foreach ($protocol in @('tcp', 'udp')) {
        Assert ($rankings.$protocol.Count -eq 1000) "1000 $protocol rankings"
        Assert (@($rankings.$protocol | Sort-Object -Unique).Count -eq 1000) "Unique $protocol rankings"
    }
    foreach ($count in @(10, 100)) {
        $top = & $scanner 127.0.0.1 --top-ports $count --timeout-ms 20
        Assert ($top.results.Count -eq $count) "Top $count selection"
    }
    $default = & $scanner 127.0.0.1 --timeout-ms 20
    Assert ($default.results.Count -eq 1000 -and $default.scans[0] -ceq '-sT') 'Default TCP top 1000'
    $udpTop = & $scanner 127.0.0.1 -sU --top-ports 10 --timeout-ms 20
    Assert (($udpTop.results.port -join ',') -eq (($rankings.udp | Select-Object -First 10) -join ',')) 'UDP uses UDP rankings'

    Assert-Rejected { & $scanner 127.0.0.1 -p 0 } 'Invalid port range'
    Assert-Rejected { & $scanner 127.0.0.1 -p 65536 } 'Invalid port range'
    Assert-Rejected { & $scanner 127.0.0.1 -p 9-1 } 'Invalid port range'
    Assert-Rejected { & $scanner 127.0.0.1 -p 80 --top-ports 10 } 'Choose -p'
    Assert-Rejected { & $scanner 127.0.0.1 --top-ports 11 } '--top-ports must'
    Assert-Rejected { & $scanner 127.0.0.1 -sT -sS } 'mutually exclusive'
    Assert-Rejected { & $scanner 127.0.0.1 -sX } 'Unknown option'
    Assert-Rejected { & $scanner 127.0.0.1 -p } 'Missing value'
    Assert-Rejected { & $scanner 'bad!hostname' } 'Invalid target'
    Assert-Rejected { & $scanner 255.255.255.255 } 'unicast'
    Assert-Rejected { & $scanner 127.0.0.1 --concurrency 0 } '--concurrency must'
    Assert-Rejected { & $scanner 127.0.0.1 -p 1 -oN (Join-Path $testDirectory 'same') -oJ (Join-Path $testDirectory 'same') } 'different paths'

    # A fixture backend tests SYN argument/result handling without Nmap or raw
    # traffic. This is not a live SYN packet test.
    if ($env:OS -eq 'Windows_NT') {
        $savedPath = $env:PATH
        try {
            $env:PATH = $testDirectory + [IO.Path]::PathSeparator + $env:PATH
            $fakeNmap = Join-Path $testDirectory 'nmap.cmd'
            '@echo off', 'set "fixture=%~dp0fixture.xml"', ':next', 'if "%~1"=="" exit /b 1', 'if "%~1"=="-oX" goto write', 'shift', 'goto next', ':write', 'copy /y "%fixture%" "%~2"', 'exit /b 0' | Set-Content -LiteralPath $fakeNmap -Encoding ascii
            $fixture = Join-Path $testDirectory 'fixture.xml'
            '<nmaprun><scaninfo type="syn"/><host><ports><extraports state="closed" count="1"/><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/></port></ports></host></nmaprun>' | Set-Content -LiteralPath $fixture
            $syn = & $scanner 127.0.0.1 -sS -p '80,81'
            Assert ($syn.results[0].state -eq 'open' -and $syn.results[1].state -eq 'closed') 'SYN explicit and aggregated XML states'
            '<nmaprun><scaninfo type="syn"/><host><ports><extraports state="closed" count="1"><extrareasons reason="reset" ports="80"/></extraports><extraports state="filtered" count="1"><extrareasons reason="no-response" ports="81"/></extraports></ports></host></nmaprun>' | Set-Content -LiteralPath $fixture
            $syn = & $scanner ::1 -sS -p '80,81'
            Assert ($syn.results[0].state -eq 'closed' -and $syn.results[1].state -eq 'filtered') 'SYN per-port aggregated mappings and IPv6 argument handling'
            '<nmaprun><scaninfo type="connect"/><host/></nmaprun>' | Set-Content -LiteralPath $fixture
            Assert-Rejected { & $scanner 127.0.0.1 -sS -p 80 } 'did not confirm a SYN scan'
            '@echo off', 'exit /b 9' | Set-Content -LiteralPath $fakeNmap -Encoding ascii
            Assert-Rejected { & $scanner 127.0.0.1 -sS -p 80 } 'exit 9'
        } finally { $env:PATH = $savedPath }
    }
    Write-Host 'All loopback integration tests passed.'
} finally {
    $listener.Stop()
    if ($null -ne $echo) { $echo.Dispose() }
    if ($null -ne $silent) { $silent.Dispose() }
    if ($null -ne $ssh) { $ssh.Dispose() }
    if ($null -ne $http) { $http.Dispose() }
    # The exact, unique directory was created by this test under the temp root.
    $resolved = [IO.Path]::GetFullPath($testDirectory)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($resolved).StartsWith('portscanner-tests-')) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
