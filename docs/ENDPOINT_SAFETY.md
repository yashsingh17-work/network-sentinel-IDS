# Endpoint safety monitoring

Network Sentinel now adds local, read-only endpoint signals alongside network
telemetry. It does not open, run, upload, delete, or quarantine downloaded
files.

## Downloads

On Windows, the application checks the configured Downloads folders every 2
seconds. By default that is the current user's `Downloads` folder. It processes
up to the 1,000 most-recent files in each configured folder, including files
already present when Network Sentinel starts. A newly seen
or changed file creates a local `DOWNLOAD_OBSERVED` alert, including its file
name, extension, size, download mark, signature status, and SHA-256 when the
file is no larger than 128 MiB.

Executable/script-like files (`.exe`, `.msi`, `.ps1`, `.bat`, `.dll`, and
similar types) without a valid Authenticode signature become a medium
`UNVERIFIED_RISKY_DOWNLOAD` alert. **Unsigned does not mean malicious**; it
means the user should verify the sender, publisher, hash, and endpoint-security
scan before opening it. A valid signature identifies a signing publisher; it
does not prove the file is safe.

Use **Audit Downloads** in the dashboard to inspect the existing files on
demand. This can take longer for a large folder because hashes are calculated
locally; the real-time watcher only evaluates new or changed files after its
first baseline pass.

Edit `config.yaml` under `sources.download_monitor.directories` if browsers on
this computer download somewhere other than the normal Downloads folder.

## Unsafe Wi-Fi

The dashboard already reads Windows Wi-Fi posture. It now creates a real alert
when Windows reports an open, WEP, or TKIP network, or when it cannot verify
the network's security. Open/legacy Wi-Fi is high severity; unverified posture
is medium severity. This is a local configuration warning, not proof that an
attacker is currently present.

## Unsafe sites

HTTPS encrypts page paths and most content. Network Sentinel can see a DNS
domain only when packet capture can see the DNS request; it cannot truthfully
inspect every full HTTPS URL from passive local capture.

For privacy, no browsing domain is sent to a third party by default. Add known
bad domains to `threat_intelligence.unsafe_domains` in `config.yaml` to enable
high-severity `SUSPICIOUS_DOMAIN` alerts on matching DNS queries. The next,
optional layer is a trusted reputation provider (for example, a commercial or
organisation-managed threat-intelligence feed). Enabling one means sharing the
domain queried with that provider and should be an explicit choice.

## Important boundary

This is an IDS and local safety monitor, not a replacement for Microsoft
Defender, browser Safe Browsing, firewall policy, or a managed EDR product.
Keep Windows and browser protections enabled. Treat alerts as investigation
evidence, not an automatic verdict.
