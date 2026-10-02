# PowerShell Penetration Testing Scripts

A collection of PowerShell scripts for authorized penetration testing and security assessments.

## Project goals

- Automate repeatable security assessment tasks.
- Support reconnaissance, enumeration, and configuration reviews within an approved scope.
- Provide readable, reusable scripts with clear parameters and documented output.

## Requirements

Requirements will vary by script. Each script should document:

- Supported operating systems and PowerShell versions.
- Required modules or external tools.
- Any required permissions, including whether administrator privileges are needed.
- Network access and target prerequisites.

Check your installed PowerShell version with:

```powershell
$PSVersionTable.PSVersion
```

## Getting started

1. Download or clone this project.
2. Review the script source and its documentation before running it.
3. Install any dependencies listed for that script.
4. Test the script in a controlled lab before using it during an assessment.
5. Run it only against targets covered by your authorization.

Use PowerShell's built-in help to inspect script usage:

```powershell
Get-Help .\invoke-portscanner.ps1 -Full
.\invoke-portscanner.ps1 -h
```

Execution syntax and parameters will be documented for each script. Follow your organization's execution policy requirements when running downloaded scripts.

## Script catalog

| Script | Purpose | Requirements |
| --- | --- | --- |
| `invoke-portscanner.ps1` | TCP connect, SYN, and UDP scanning, progress reporting, TCP service checks, and text/JSON/XML/grepable exports | PowerShell 5.1 or 7; SYN additionally requires Nmap and packet-capture privileges |

## Port scanner

The scanner accepts IPv4/IPv6 addresses, hostnames, and IPv4/IPv6 CIDRs directly or through `-iL`. Multiple targets can be separated by spaces or commas. Target files accept whitespace, commas, blank lines, and `#` comments. Hostnames resolve to all available A/AAAA addresses using the system resolver. Duplicate resolved addresses and ports are removed before scanning. Resolution failures stop the run before port scanning.

CIDRs are normalized to their network boundary. IPv4 subnets omit network and broadcast addresses, except `/31` and `/32`, which include every address. IPv6 subnets include every unicast address; unspecified and multicast addresses are skipped. Expansion is limited to 65536 addresses per CIDR and 65536 unique targets overall by default. Use `--max-targets` to change the limit (1–1000000). Oversized subnets are rejected before enumeration.

The default scan is **TCP connect against the top 1000 TCP ports**, with a 1000 ms timeout per probe and up to 64 concurrent probes. UDP uses a separate frequency-ranked list. Keep `data/top-ports.json` beside the script in its `data` directory; explicit `-p` scans do not need that file.

```powershell
# Default TCP scan of the top 1000 ports
.\invoke-portscanner.ps1 192.0.2.10

# Resolve a hostname and scan specific ports
.\invoke-portscanner.ps1 scanme.nmap.org -p '80,443'

# Identify services on open TCP ports and export the results
.\invoke-portscanner.ps1 192.0.2.10 -sT -sV -p '22,80,443,8080' -oA services

# Scan an IPv4 subnet or a small IPv6 subnet
.\invoke-portscanner.ps1 192.0.2.0/24 --top-ports 10
.\invoke-portscanner.ps1 '2001:db8::/126' -p '22,443'

# Specific ports and ranges; export every format
.\invoke-portscanner.ps1 192.0.2.10 192.0.2.11 -sT -p '22,80,443,8000-8010' -oA assessment

# Read targets from a file and scan the top 100 TCP ports
.\invoke-portscanner.ps1 -iL targets.txt --top-ports 100 -oN tcp.txt

# UDP top 10 with JSON output
.\invoke-portscanner.ps1 192.0.2.10 -sU --top-ports 10 -oJ udp.json

# Combine native TCP and UDP scans with custom timing
.\invoke-portscanner.ps1 -iL targets.txt -sT -sU -p '53,80,443' --timeout-ms 3000 --concurrency 32

# True SYN scan using the Nmap backend
.\invoke-portscanner.ps1 192.0.2.10 -sS -p '1-1024' -oX syn.xml

# All 65535 ports: quote the dash used as the port specification
.\invoke-portscanner.ps1 192.0.2.10 -p '-'
```

The example IP addresses are documentation placeholders; replace them with authorized targets.

| Option | Meaning |
| --- | --- |
| `-sT` | Native TCP connect scan; completes a connection when a port is open |
| `-sS` | True SYN scan through Nmap; never silently substitutes a connect scan |
| `-sU` | Native UDP scan with an empty datagram |
| `-sV` | Check open TCP services using the TCP reference table and banner recognition |
| `--no-progress` | Suppress scan and service-check progress bars |
| `-iL <file>` | Read IPs, hostnames, and CIDRs from a file; can be combined with direct targets |
| `-p <ports>` | Comma-separated ports and inclusive ranges, or `'-'` for 1–65535 |
| `--top-ports <10\|100\|1000>` | Use the most frequent ports for each selected protocol |
| `--timeout-ms <1–60000>` | Native probe timeout; default 1000 |
| `--concurrency <1–1024>` | Maximum outstanding native probes per target; default 64 |
| `--max-targets <1–1000000>` | Maximum addresses per CIDR and unique resolved targets overall; default 65536 |
| `-oN <file>` | Plain text |
| `-oJ <file>` | JSON |
| `-oX <file>` | XML |
| `-oG <file>` | Grepable text |
| `-oA <basename>` | Generate `<basename>.txt`, `.json`, `.xml`, and `.gnmap` |
| `-h`, `--help` | Show CLI help |

Flags are case-sensitive. Choose either `-p` or `--top-ports`. Combine `-sU` with either TCP mode; `-sT` and `-sS` are mutually exclusive. Targets and scan modes run sequentially, with bounded concurrency within native scans.

Progress is shown by default through PowerShell's `Write-Progress`: completed probes across all targets and scan modes, percentage, and the current target/scan. Native counts update as probes finish. SYN progress uses Nmap's timing reports and is an estimate until a host scan completes. Service checking has its own progress phase. Progress does not enter the returned report or exports; use `--no-progress` for quiet automation or `$ProgressPreference = 'SilentlyContinue'` to suppress the bar in your host.

### TCP service checks (`-sV`)

Keep `services_tcp.csv` beside the script. Despite its extension, this supplied reference is a headerless, tab/whitespace-separated table with service names, `port/tcp`, frequency, and optional descriptions. The script reads this format directly. It also accepts the filename `servivces_tcp.csv` if the correctly spelled file is absent.

After port scanning, `-sV` opens a TCP connection to each open TCP port and reads up to 4096 bytes of a banner. Mapped plaintext `http`, `http-alt`, and `http-proxy` services receive a `HEAD / HTTP/1.0` request; other services are checked passively. Recognized SSH, HTTP, SMTP, FTP, POP3, and IMAP banners can replace the port-based hint, including on nonstandard ports. SSH software identifiers and HTTP `Server` headers populate `version` when present. Control characters in banners and detected versions are escaped for display and export.

The service fields distinguish observation from inference:

- `service`: observed service name, reference-table hint, or `unknown`.
- `serviceSource`: `banner` for a recognized response, `port-table` for a hint, or `unknown` when neither is available.
- `version`: available SSH/HTTP identification text; banners are self-reported and do not prove a product version.
- `banner`: escaped response text, if received.
- `serviceCheckReason`: response, timeout, or connection-error detail.

Service checks use `--timeout-ms` and `--concurrency`. A silent service keeps its hint without being marked as confirmed. TLS negotiation, UDP service checks, and comprehensive Nmap version fingerprints are not implemented. `-sU -sV` alone therefore performs no service probes. With `-sS -sV`, the SYN phase still uses Nmap and the service phase makes regular TCP connections through .NET.

### SYN requirements

TCP connect and UDP scans run directly through .NET sockets and do not require Nmap. **SYN mode uses an external Nmap backend**, because [Windows restricts raw TCP sockets](https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2). Install [Nmap](https://nmap.org/download.html), ensure `nmap` is on `PATH`, and install Npcap for Windows packet capture. Run with the privileges required by Nmap/Npcap; see [Nmap's Windows documentation](https://nmap.org/book/inst-windows.html). On Unix, SYN scans generally require root or suitable raw-packet privileges. The script does not install dependencies or elevate itself.

The script resolves hostnames and expands CIDRs before invoking SYN mode. Nmap receives the resolved addresses with its own DNS lookup disabled and without a preliminary host-discovery gate. Nmap controls SYN retries and timing; `--timeout-ms` and `--concurrency` apply only to native TCP/UDP scans. A failed SYN backend aborts the run before final exports.

### Results and limitations

- TCP connection success means `open`; connection refusal means `closed`. A connect timeout is reported as `filtered`, with reason `connect-timeout`; congestion or a short timeout can produce the same observation.
- A UDP reply means `open`; a socket error indicating port rejection means `closed`. Silence means `open|filtered`. Empty probes do not elicit responses from many real UDP services. The scanner does not include Nmap's protocol-specific payloads or retries; [Nmap's UDP scan documentation](https://nmap.org/book/scan-methods-udp-scan.html) explains these limitations.
- Local socket failures such as access denial are reported as `error`, with the socket error in `reason`.
- SYN states come from Nmap. When its XML aggregates multiple omitted states without per-port mappings, affected ports are marked `unknown` rather than assigned a guessed state.
- Service checking is limited to the TCP reference table and the banners described above. There is no OS fingerprinting or adaptive timing. A timeout does not establish that a host is offline.

All exports contain every scanned port. Plain text uses tab-separated fields; grepable text uses one `Host:` line per address. **JSON and XML use this project's schema, not Nmap's output schema**; Nmap tools may not accept them. JSON includes run timestamps, targets, scan modes, port selection, native timing settings, and results. Each result includes `address`, `port`, `protocol`, `scan`, `state`, `reason`, and `elapsedMs`. SYN probe elapsed time is unavailable and represented as JSON `null` or an empty XML attribute.

Output files use UTF-8, must not already exist, and require existing parent directories.

The report and JSON export preserve original target inputs in `requestedTargets`; `targets` and result addresses contain the resolved, expanded IP addresses. The script also returns a report object for PowerShell pipelines:

```powershell
$report = .\invoke-portscanner.ps1 192.0.2.10 -p '22,80,443'
$report.results | Where-Object state -eq 'open'
```

### Port ranking data

`data/top-ports.json` contains 1000 unique port numbers per protocol ranked by observed open-port frequency from [Nmap's service database](https://raw.githubusercontent.com/nmap/nmap/master/nmap-services), retrieved on 2026-10-02. Equal frequencies are ordered by port number, so tie-boundary selection can differ from Nmap. It includes port numbers and provenance, without service names or the full database. See [Nmap's port frequency documentation](https://nmap.org/book/nmap-services.html).

## Development guidelines

- Use descriptive filenames, functions, and parameter names.
- Include comment-based help with a synopsis, description, parameters, and examples.
- Validate inputs and handle errors with actionable messages.
- Document changes a script makes to the target or local system and any cleanup steps.
- Avoid hard-coded credentials and keep secrets out of source control and logs.
- Document and require explicit opt-in for actions that modify systems.
- Test in an isolated lab and record supported PowerShell versions.

## Authorized use

Use these scripts only on systems you own or have explicit permission to assess. Agree on the target scope and rules of engagement before running them. Assessment output may contain sensitive information; store and share it according to the engagement's requirements.

## License

A license has not yet been selected. Add a `LICENSE` file to define terms for use, modification, and redistribution.
