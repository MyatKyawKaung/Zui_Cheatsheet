# Zui PCAP Investigation Cheatsheet

This cheatsheet is for offline/passive PCAP analysis in Zui using Zeek, Suricata, and Zed queries.

## 1. Basic Zui Workflow

1. Open Zui.
2. Import or drag the PCAP into Zui.
3. Wait for Zui/Brimcap to process the PCAP.
4. Zui generates Zeek and Suricata records.
5. Start with broad inventory queries.
6. Pivot from alerts to DNS, HTTP, TLS, files, and connection records.
7. Document evidence: timestamp, source, destination, protocol, domain, URL, filename, hash, alert signature, and action.

## 2. Common Record Types

| Record Type | Meaning |
|---|---|
| `_path=="conn"` | Zeek connection summary |
| `_path=="dns"` | DNS queries and responses |
| `_path=="http"` | HTTP requests and responses |
| `_path=="ssl"` | TLS/SSL metadata, SNI, JA3/JA3S |
| `_path=="files"` | Files observed by Zeek |
| `_path=="ftp"` | FTP commands and replies |
| `_path=="smtp"` | SMTP traffic if detected |
| `_path=="notice"` | Zeek notices |
| `_path=="weird"` | Zeek protocol anomalies |
| `_path=="smb_files"` | SMB file activity |
| `_path=="smb_mapping"` | SMB share mappings |
| `_path=="dce_rpc"` | DCE/RPC activity |
| `event_type=="alert"` | Suricata IDS alert |

## 3. Start Here: Dataset Overview

Show all available Zeek streams and event counts:

```zed
count() by _path | sort -r
```

Show Zeek records vs Suricata alerts:

```zed
zeek:=count(has(_path)), alerts:=count(has(event_type=="alert"))
```

Show first few records:

```zed
head 20
```

Show records in time order:

```zed
sort ts
```

## 4. Suricata Alert Triage

Alert count by signature:

```zed
event_type=="alert" | count() by alert.signature | sort -r
```

Alert count by severity and category:

```zed
event_type=="alert" | count() by alert.severity, alert.category | sort -r
```

Detailed alert view:

```zed
event_type=="alert"
| cut ts, src_ip, src_port, dest_ip, dest_port, proto, app_proto, alert.severity, alert.category, alert.signature, alert.action
| sort ts
```

Group alert signatures by source/destination:

```zed
event_type=="alert"
| alerts:=union(alert.signature) by src_ip, dest_ip
```

Find high-severity Suricata alerts:

```zed
event_type=="alert" alert.severity<=2
| cut ts, src_ip, src_port, dest_ip, dest_port, app_proto, alert.severity, alert.signature, alert.category
| sort ts
```

Pivot idea:
After finding an alert, pivot using the same `src_ip`, `dest_ip`, ports, and timestamp in `conn`, `dns`, `http`, `ssl`, `files`, or protocol-specific logs.

## 5. Connection Analysis

All unique connections:

```zed
_path=="conn"
| cut id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service
| sort
| uniq
```

Top source hosts:

```zed
_path=="conn" | count() by id.orig_h | sort -r
```

Top destination hosts:

```zed
_path=="conn" | count() by id.resp_h | sort -r
```

Top destination ports:

```zed
_path=="conn" | count() by id.resp_p, proto, service | sort -r
```

High-volume connections:

```zed
_path=="conn"
| put total_bytes:=orig_bytes+resp_bytes
| sort -r total_bytes
| cut ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, service, duration, orig_bytes, resp_bytes, total_bytes, conn_state
| head 25
```

Connections from one suspected host:

```zed
_path=="conn" id.orig_h==10.2.3.101
| sort ts
| cut ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state
```

Connections to one suspicious external IP:

```zed
_path=="conn" id.resp_h==162.241.123.75 OR id.orig_h==162.241.123.75
| sort ts
```

## 6. DNS Investigation

All DNS queries:

```zed
_path=="dns"
| cut ts, id.orig_h, id.resp_h, query, qtype_name, rcode_name, answers
| sort ts
```

Top DNS queries:

```zed
_path=="dns" | count() by query | sort -r
```

Top parent domains:

```zed
_path=="dns"
| count() by domain:=join(split(query,".")[-2:],".")
| sort -r
```

Failed DNS / NXDOMAIN:

```zed
_path=="dns" rcode_name!="NOERROR"
| count() by query, rcode_name
| sort -r
```

DNS queries from one host:

```zed
_path=="dns" id.orig_h==10.2.3.101
| cut ts, query, qtype_name, rcode_name, answers
| sort ts
```

Search for suspicious TLDs:

```zed
_path=="dns" (grep(/\.su$/, query) OR grep(/\.cc$/, query) OR grep(/\.top$/, query) OR grep(/\.xyz$/, query))
| cut ts, id.orig_h, query, rcode_name, answers
| sort ts
```

Long DNS queries, possible tunneling indicator:

```zed
_path=="dns"
| put qlen:=len(query)
| where qlen > 80
| cut ts, id.orig_h, query, qtype_name, rcode_name, qlen
| sort -r qlen
```

## 7. HTTP Investigation

All HTTP requests:

```zed
_path=="http"
| cut ts, uid, id.orig_h, id.resp_h, id.resp_p, method, host, uri, status_code, user_agent, request_body_len, response_body_len
| sort ts
```

HTTP POST requests:

```zed
_path=="http" method=="POST"
| cut ts, uid, id.orig_h, id.resp_h, host, uri, status_code, request_body_len, response_body_len, user_agent
| sort ts
```

Top HTTP hosts:

```zed
_path=="http" | count() by host | sort -r
```

Top user agents:

```zed
_path=="http" | count() by user_agent | sort -r
```

Large HTTP responses:

```zed
_path=="http"
| sort -r response_body_len
| cut ts, uid, id.orig_h, id.resp_h, host, uri, status_code, response_body_len
| head 25
```

Suspicious API-style requests:

```zed
_path=="http" (grep(/api/i, uri) OR grep(/token/i, uri) OR grep(/id=/i, uri))
| cut ts, id.orig_h, id.resp_h, method, host, uri, status_code, user_agent
| sort ts
```

Cleartext credential-looking HTTP:

```zed
_path=="http" (grep(/password/i, uri) OR grep(/passwd/i, uri) OR grep(/pwd/i, uri) OR grep(/token/i, uri))
| cut ts, id.orig_h, id.resp_h, method, host, uri, status_code
| sort ts
```

## 8. TLS / SSL Investigation

TLS/SNI overview:

```zed
_path=="ssl"
| cut ts, uid, id.orig_h, id.resp_h, id.resp_p, server_name, version, cipher, validation_status, ja3, ja3s
| sort ts
```

Top SNI values:

```zed
_path=="ssl" | count() by server_name | sort -r
```

TLS sessions from one host:

```zed
_path=="ssl" id.orig_h==10.2.3.101
| cut ts, uid, id.resp_h, id.resp_p, server_name, validation_status, ja3, ja3s
| sort ts
```

TLS sessions with certificate validation issues:

```zed
_path=="ssl" validation_status!="ok"
| cut ts, id.orig_h, id.resp_h, server_name, validation_status, subject, issuer
| sort ts
```

Top JA3 fingerprints:

```zed
_path=="ssl" ja3!=null | count() by ja3 | sort -r
```

Suspicious TLS note:
TLS metadata does not reveal encrypted payload content. Do not claim file contents or commands inside HTTPS unless you have TLS decryption or other supporting evidence.

## 9. File Transfer Investigation

All files observed by Zeek:

```zed
_path=="files"
| cut ts, fuid, uid, id.orig_h, id.resp_h, source, mime_type, filename, seen_bytes, total_bytes, md5, sha1, sha256
| sort ts
```

Files with hashes:

```zed
_path=="files" (md5!=null OR sha1!=null OR sha256!=null)
| cut ts, fuid, source, mime_type, filename, seen_bytes, total_bytes, md5, sha1, sha256
| sort ts
```

Potential executables/scripts:

```zed
_path=="files" mime_type!=null
| search "application/x-dosexec" OR "application/x-executable" OR "script" OR "powershell" OR "javascript"
| cut ts, fuid, uid, id.orig_h, id.resp_h, source, mime_type, filename, seen_bytes, md5, sha1, sha256
| sort ts
```

Large files:

```zed
_path=="files"
| sort -r seen_bytes
| cut ts, fuid, source, mime_type, filename, seen_bytes, total_bytes, md5, sha1, sha256
| head 25
```

## 10. FTP Investigation / Exfiltration

All FTP commands:

```zed
_path=="ftp"
| cut ts, uid, id.orig_h, id.resp_h, id.resp_p, user, command, arg, reply_code, reply_msg, fuid
| sort ts
```

FTP uploads using STOR:

```zed
_path=="ftp" command=="STOR"
| cut ts, uid, id.orig_h, id.resp_h, user, command, arg, reply_code, reply_msg, fuid
| sort ts
```

FTP credentials observed by Zeek:

```zed
_path=="ftp" user!=null
| cut ts, id.orig_h, id.resp_h, user, command, reply_code, reply_msg
| sort ts
```

FTP data channels:

```zed
_path=="conn" service=="ftp-data"
| cut ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, duration, orig_bytes, resp_bytes, conn_state
| sort ts
```

FTP files:

```zed
_path=="files" source=="FTP_DATA"
| cut ts, fuid, uid, id.orig_h, id.resp_h, source, mime_type, seen_bytes, md5, sha1, sha256, local_orig, is_orig
| sort ts
```

AgentTesla-style FTP exfil alert:

```zed
event_type=="alert" grep(/AgentTesla/i, alert.signature)
| cut ts, src_ip, src_port, dest_ip, dest_port, alert.severity, alert.signature, alert.category, alert.action
| sort ts
```

## 11. SMB / DCE-RPC / Lateral Movement

Windows networking activity:

```zed
grep(smb*, _path) OR _path=="dce_rpc"
```

SMB file activity:

```zed
_path=="smb_files"
| cut ts, uid, id.orig_h, id.resp_h, name, path, action, size, fuid
| sort ts
```

SMB share mappings:

```zed
_path=="smb_mapping"
| cut ts, uid, id.orig_h, id.resp_h, path, service, native_file_system
| sort ts
```

DCE/RPC activity:

```zed
_path=="dce_rpc"
| cut ts, uid, id.orig_h, id.resp_h, rtt, named_pipe, endpoint, operation
| sort ts
```

Common Windows admin ports:

```zed
_path=="conn" (id.resp_p==445 OR id.resp_p==135 OR id.resp_p==139 OR id.resp_p==3389 OR id.resp_p==5985 OR id.resp_p==5986)
| cut ts, id.orig_h, id.resp_h, id.resp_p, service, conn_state, duration, orig_bytes, resp_bytes
| sort ts
```

RDP activity:

```zed
_path=="conn" id.resp_p==3389
| cut ts, id.orig_h, id.resp_h, id.resp_p, conn_state, duration, orig_bytes, resp_bytes
| sort ts
```

## 12. Beaconing / C2 Hunting

Repeated source/destination/port pairs:

```zed
_path=="conn"
| count() by id.orig_h, id.resp_h, id.resp_p, proto, service
| sort -r
```

Pivot on one suspected pair:

```zed
_path=="conn" id.orig_h==10.2.3.101 id.resp_h==162.241.123.75
| sort ts
| cut ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, service, duration, orig_bytes, resp_bytes, conn_state
```

Low-byte repeated outbound sessions:

```zed
_path=="conn"
| put total_bytes:=orig_bytes+resp_bytes
| where total_bytes < 5000
| count() by id.orig_h, id.resp_h, id.resp_p, service
| sort -r
```

Possible direct-to-IP HTTP/TLS:

```zed
_path=="http" host==null
| cut ts, id.orig_h, id.resp_h, method, uri, status_code, user_agent
| sort ts
```

```zed
_path=="ssl" server_name==null
| cut ts, id.orig_h, id.resp_h, id.resp_p, ja3, ja3s
| sort ts
```

## 13. IOC Searching

Search any string anywhere:

```zed
"example.com"
```

Search a domain in DNS:

```zed
_path=="dns" query=="example.com"
```

Search an IP in connections:

```zed
_path=="conn" id.orig_h==192.0.2.10 OR id.resp_h==192.0.2.10
```

Search an IP across all records:

```zed
192.0.2.10
```

Search URL/domain in HTTP:

```zed
_path=="http" host=="example.com"
```

Search a file hash:

```zed
"d41d8cd98f00b204e9800998ecf8427e"
```

Search Suricata signature text:

```zed
event_type=="alert" grep(/AgentTesla/i, alert.signature)
```

## 14. Useful Pivot Strategy

### From Suricata Alert

1. Start with:

```zed
event_type=="alert" | cut ts, src_ip, src_port, dest_ip, dest_port, app_proto, alert.signature
```

2. Pivot to connection:

```zed
_path=="conn" id.orig_h==<src_ip> id.resp_h==<dest_ip>
```

3. Pivot to DNS near the same time:

```zed
_path=="dns" id.orig_h==<src_ip>
```

4. Pivot to protocol records:

```zed
_path=="http" id.orig_h==<src_ip>
```

```zed
_path=="ssl" id.orig_h==<src_ip>
```

```zed
_path=="files" id.orig_h==<src_ip>
```

### From Suspicious Domain

1. DNS:

```zed
_path=="dns" query=="suspicious-domain.com"
```

2. Note the resolved IP.
3. Pivot to connections:

```zed
_path=="conn" id.resp_h==<resolved_ip>
```

4. Pivot to HTTP/TLS:

```zed
_path=="http" host=="suspicious-domain.com"
```

```zed
_path=="ssl" server_name=="suspicious-domain.com"
```

### From File Hash

1. Search file records:

```zed
_path=="files" md5=="<hash>" OR sha1=="<hash>" OR sha256=="<hash>"
```

2. Note `uid` and `fuid`.
3. Pivot to connection by `uid`:

```zed
_path=="conn" uid=="<uid>"
```

## 15. Investigation Notes Template

Use this structure while investigating:

```text
Case Name:
PCAP File:
Time Range:
Patient Zero / Primary Host:
Internal DNS Server:
Important External IPs:
Important Domains:
Suspicious URLs:
Alert Signatures:
Files / Hashes:
Exfiltration Evidence:
C2 / Beaconing Evidence:
Final Assessment:
Recommended Actions:
```

## 16. Report Evidence Checklist

Before writing a finding, capture:

- Timestamp
- Source IP / host
- Destination IP / domain
- Protocol and port
- Zeek record type
- Suricata signature and severity, if any
- DNS query and answer
- HTTP method, host, URI, status code, user agent
- TLS SNI, JA3/JA3S, cert validation
- File name, MIME type, size, hash
- FTP username, command, filename, data-channel evidence if applicable
- Whether the traffic was allowed, blocked, successful, failed, or unresolved
- Analysis limitation, especially encrypted payloads or missing endpoint data

## 17. Cautious Verdict Language

Use:

- “The traffic indicates…”
- “The activity appears consistent with…”
- “Based on the PCAP evidence…”
- “This requires endpoint validation…”
- “There is no endpoint evidence in the provided PCAP to confirm…”

Avoid unless strongly supported:

- “The host is compromised”
- “The attack was fully successful”
- “The malware was removed”
- “The threat was contained”

## 18. Quick Query Set for Malware PCAPs

Run these first:

```zed
count() by _path | sort -r
```

```zed
event_type=="alert" | count() by alert.severity, alert.category, alert.signature | sort -r
```

```zed
_path=="dns" | cut ts, id.orig_h, query, rcode_name, answers | sort ts
```

```zed
_path=="http" | cut ts, id.orig_h, id.resp_h, method, host, uri, status_code, user_agent | sort ts
```

```zed
_path=="ssl" | cut ts, id.orig_h, id.resp_h, server_name, validation_status, ja3, ja3s | sort ts
```

```zed
_path=="files" | cut ts, fuid, uid, source, mime_type, filename, seen_bytes, md5, sha1, sha256 | sort ts
```

```zed
_path=="conn" | put total_bytes:=orig_bytes+resp_bytes | sort -r total_bytes | cut ts, uid, id.orig_h, id.resp_h, id.resp_p, service, duration, total_bytes | head 25
```
