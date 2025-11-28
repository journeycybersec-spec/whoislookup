<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />

</head>
<body>

<h1>Whois_Lookup — OSINT WHOIS + DNSSEC signal</h1>

<p><strong>TL;DR:</strong> A small, focused module that fetches WHOIS, verifies DNSSEC via DS records, flags risky signals (new domain, anonymous registrant, unsigned DNSSEC, etc.), and prints a concise verdict (<strong>Safe ✅ / Warning ⚠️ / Not Safe ❌</strong>). Designed to be a building block in a larger OSINT pipeline.</p>

<blockquote>
  <p>This module is intended to become a component of a broader OSINT program. Drop it into your recon triage to quickly score domains by basic registration hygiene.</p>
</blockquote>

<hr />

<h2>What it does</h2>
<ol>
  <li><strong>Fetches WHOIS data</strong> and normalizes common fields (creation/expiration/update dates, nameservers, status).</li>
  <li><strong>Computes domain age</strong> in days to highlight <strong>new domains</strong> (&lt; 180 days).</li>
  <li><strong>Verifies DNSSEC via DS records</strong> (optional): if <code>dnspython</code> is available, queries <code>DS</code> at the parent to confirm signed delegation. This avoids “stale/ambiguous” WHOIS DNSSEC text.</li>
  <li><strong>Detects registrant privacy/proxy patterns</strong> using curated keywords and known privacy email domains.</li>
  <li><strong>Produces a Red-Flags checklist</strong> and a <strong>final judgment</strong>:
    <ul>
      <li>If any non-anonymity flag is Not Safe → <strong>Not Safe ❌</strong></li>
      <li>Else if only anonymity is Not Safe → <strong>Warning ⚠️</strong></li>
      <li>Else → <strong>Safe ✅</strong></li>
    </ul>
  </li>
  <li><strong>CLI entry point</strong> for quick checks: <span class="kbd">python whois_lookup.py &lt;domain&gt;</span></li>
</ol>

<hr />

<h2>Why it’s useful (OSINT use-cases)</h2>
<ul>
  <li><strong>Triage at scale:</strong> Quickly spot throwaway or suspicious domains during investigations.</li>
  <li><strong>Signal enrichment:</strong> Add DNSSEC and registrant-anonymity context to your data lake.</li>
  <li><strong>Hunting heuristics:</strong> Filter candidate IOCs by age + DNSSEC posture + privacy signals.</li>
  <li><strong>Human-friendly output:</strong> Fits terminal-driven workflows and rapid analyst review.</li>
</ul>

<hr />

<h2>Features in detail</h2>

<h3>WHOIS fetch &amp; normalization</h3>
<ul>
  <li>Uses the <code>python-whois</code> library to retrieve records and normalize common fields.</li>
  <li>Defensive getters handle library field-shape variance (strings vs lists).</li>
</ul>

<h3>Domain age</h3>
<ul>
  <li>Parses <code>creation_date</code> variants; returns <code>0</code> on unknown/invalid to avoid crashes.</li>
  <li>Age &lt; <strong>180 days</strong> triggers a <strong>Not Safe ❌</strong> flag “New domain (under 6 months)”.</li>
</ul>

<h3>DNSSEC (verified via DS)</h3>
<ul>
  <li><strong>Preferred signal:</strong> a live DNS <code>DS</code> check with <code>dnspython</code> when available.</li>
  <li><strong>Outcomes:</strong> <code>signed</code> | <code>unsigned</code> | <code>unknown</code>.</li>
  <li>If not <strong>signed</strong>, the checklist includes <strong>“No DNSSEC found: Not Safe ❌”</strong>.</li>
  <li>If <code>dnspython</code> is missing or there’s a timeout, falls back to WHOIS <code>dnssec</code> text with conservative normalization.</li>
</ul>

<h3>Registrant privacy detection</h3>
<ul>
  <li>Scans WHOIS text (including nested contact/VCARD arrays) for privacy/proxy indicators and well-known privacy email domains.</li>
  <li>If detected → <strong>“Anonymous registrant detected: Not Safe ❌”</strong>; however, the <strong>final judgment</strong> is only <strong>Warning ⚠️</strong> if this is the only failing signal.</li>
</ul>

<h3>Other checks</h3>
<ul>
  <li><strong>Frequent ownership changes:</strong> Placeholder (API parity); currently surfaces the registrar string.</li>
  <li><strong>Offshore registrar (naïve):</strong> Flags “offshore” if the registrar string literally contains that token.</li>
</ul>

<hr />

<h2>CLI usage</h2>
<pre><code>python whois_lookup.py example.com
</code></pre>

<p><strong>Sample output (abridged):</strong></p>
<pre><code>Performing WHOIS lookup for example.com...

Domain Information for: example.com
========================================
Registered On    : 1995-08-14 04:00:00
Expires On       : 2030-08-13 23:59:59
Updated On       : 2024-07-01 12:34:56
Domain Status    : clientTransferProhibited
Name Servers     : a.iana-servers.net, b.iana-servers.net
----------------------------------------
Registrant Organization : Example Org
Domain Age (Days)      : 11000 days
DNSSEC Status          : signed

Red Flags Checklist:
 - New domain (under 6 months): Safe ✅
 - Anonymous registrant detected: Safe ✅
 - Frequent ownership changes detected: Safe ✅
 - No DNSSEC found: Safe ✅
 - Offshore registrar detected: Safe ✅

Final Judgment:
Safe ✅
========================================
</code></pre>

<hr />

<h2>Linux requirements &amp; setup</h2>

<h3>OS &amp; Python</h3>
<ul>
  <li><strong>Linux (x86_64/ARM)</strong></li>
  <li><strong>Python 3.8+</strong> (tested on 3.10/3.11)</li>
</ul>

<h3>Network</h3>
<ul>
  <li>Outbound <strong>TCP/43</strong> (WHOIS) and <strong>DNS/UDP+TCP</strong> required for live lookups.</li>
  <li>Some WHOIS registries apply rate-limits; consider backoff when batch-running.</li>
</ul>

<h3>System packages</h3>
<p>No native build tools required for the default path. If your distro ships a conflicting <code>whois</code> system utility, it does <strong>not</strong> affect <code>python-whois</code> (this script uses the Python library, not the shell tool).</p>

<h3>Python packages</h3>
<p>Install via <code>pip</code>:</p>
<pre><code>pip install -r requirements.txt
</code></pre>
<ul>
  <li><code>python-whois</code> — WHOIS fetch/parse</li>
  <li><code>dnspython</code> — (optional) live DS verification for DNSSEC</li>
</ul>
<p><em>If you skip <code>dnspython</code>, DNSSEC will fall back to WHOIS text and may show <code>unknown</code>.</em></p>

<hr />

<h2>Integration in a larger OSINT program</h2>
<ul>
  <li><strong>Library use:</strong> import and call <code>whois_lookup(domain)</code> or reuse helpers like <code>get_dnssec_status</code>, <code>get_domain_age_days</code>, and <code>check_red_flags</code>.</li>
  <li><strong>Pipelining:</strong> Wrap the CLI in your orchestrator, capture stdout, or refactor output into JSON in your app layer.</li>
  <li><strong>Extensibility:</strong> Replace <code>ownership_change_check</code> with a real registrar/registry history API; augment the red-flags map to fit your scoring model.</li>
</ul>

<hr />

<h2>Limitations / notes</h2>
<ul>
  <li>WHOIS data quality varies by TLD/registry; GDPR redactions are common.</li>
  <li>DNS timeouts and registry rate-limits can yield <code>unknown</code> for DNSSEC.</li>
  <li>Heuristics are intentionally conservative and should be combined with other signals.</li>
</ul>

<hr />

<h2>License</h2>
<p>Non-Commercial Software License (NCSL) v1.0</p>

</body>
</html>
