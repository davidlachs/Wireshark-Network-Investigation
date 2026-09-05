# Case 01 — From DNS Resolution to Decrypted HTTPS Traffic

## Overview

This investigation follows a normal web connection to `consolekings.com` from the first DNS lookup through TCP connection setup and TLS-encrypted HTTPS traffic.

I used Wireshark to isolate the website's traffic, identify the TCP three-way handshake, inspect the TLS handshake, and then perform a second controlled capture in which I supplied Firefox TLS session secrets to Wireshark. That allowed me to see the HTTP/2 request and response that were normally hidden inside TLS encryption.

**Why this matters:** Security analysts often begin with a large packet capture and must narrow it to the specific host, connection, and protocol activity relevant to an investigation.

---

## Objectives

- Observe how a domain name is resolved to an IP address.
- Identify a TCP three-way handshake (`SYN → SYN-ACK → ACK`).
- Identify HTTPS traffic using TCP port 443.
- Observe a TLS Client Hello containing the requested hostname.
- Compare encrypted TLS application data with the same traffic after authorized decryption.
- Practice using Wireshark display filters and stream-following to isolate one network conversation.

---

## Lab Environment

| Item | Details |
|---|---|
| Operating system | macOS |
| Network analyzer | Wireshark |
| Browser | Firefox |
| Capture interface | Wi-Fi (`en0`) |
| Website | `consolekings.com` |
| Traffic | DNS, TCP, TLS, HTTP/2 |
| Scope | Traffic generated from my own device in a controlled lab |

---

## Investigation Summary

```text
Domain name
    |
    v
DNS lookup
consolekings.com -> 216.150.1.1
    |
    v
TCP connection
SYN -> SYN-ACK -> ACK
    |
    v
TLS handshake
Client Hello / Server Hello
    |
    v
Encrypted application data
    |
    v
TLS session keys supplied to Wireshark
    |
    v
HTTP/2 request and response visible
```

---

## 1. DNS Resolution

I first isolated DNS traffic for the target domain with:

```text
dns.qry.name == "consolekings.com"
```

The capture showed an **A record** query for `consolekings.com`. The DNS response returned:

```text
consolekings.com -> 216.150.1.1
```

An A record maps a hostname to an IPv4 address. I also observed an AAAA query, which is used to request an IPv6 address.

The DNS packets traveled over UDP port 53. In this capture, the DNS exchange itself used IPv6 between my device and its configured DNS resolver.

![DNS query and response](screenshots/01-dns-resolution.png)

### What this demonstrated

Before a client can connect to a website by name, it usually needs to learn an IP address for that hostname. DNS provides that mapping.

### Security relevance

DNS is useful during network investigations because domain lookups can show which services a host is attempting to contact. Suspicious or unexpected DNS activity can provide an early lead during incident analysis.

---

## 2. TCP Three-Way Handshake

After identifying the IPv4 address returned by DNS, I filtered for TCP traffic involving that address:

```text
ip.addr == 216.150.1.1 && tcp
```

The connection began with:

```text
192.168.1.95:55772  -> 216.150.1.1:443   SYN
216.150.1.1:443     -> 192.168.1.95:55772 SYN, ACK
192.168.1.95:55772  -> 216.150.1.1:443   ACK
```

This is the TCP three-way handshake:

```text
Client                         Server

SYN -------------------------->
    <------------------ SYN-ACK
ACK -------------------------->

        Connection established
```

The client used temporary port `55772`, while the server used port `443`, the standard port for HTTPS.

![TCP handshake and TLS connection](screenshots/02-tcp-three-way-handshake-and-tls.png)

### Private addressing and NAT

Wireshark was capturing traffic directly on my laptop, so it showed the laptop's private IPv4 address, `192.168.1.95`.

If my network gateway performs Network Address Translation (NAT), that translation happens after the packet leaves the laptop. A capture taken on the laptop therefore sees the packet before the gateway replaces the private source address with a public-facing address.

I did not capture traffic on the WAN side of the gateway, so the NAT translation itself was not directly observed in this lab.

### Security relevance

TCP flags and connection state help analysts determine whether connections were successfully established and can also help identify behavior such as repeated connection attempts, scanning, resets, or retransmissions.

---

## 3. TLS Encryption

Immediately after TCP connection setup, Wireshark showed a TLS handshake.

One packet contained:

```text
Client Hello (SNI=consolekings.com)
```

SNI stands for **Server Name Indication**. In this capture, it identified the hostname the client wanted to reach even though the connection was being made to an IP address.

After the TLS handshake, most of the web traffic appeared only as:

```text
Application Data
```

The content was not readable from the packet capture alone because HTTPS was protected by TLS.

### Key observation

TLS encrypted the application payload, but some network metadata remained observable, including the source and destination addresses, ports, packet timing, and the hostname visible in this Client Hello.

---

## 4. Authorized TLS Decryption

To demonstrate what TLS was protecting, I performed a second controlled capture.

Firefox was launched with the `SSLKEYLOGFILE` environment variable enabled so that it recorded the TLS session secrets for my own browser session. I then configured Wireshark's TLS settings to use that key log file.

With the correct session secrets available, Wireshark was able to decrypt the TLS payload and identify the application protocol as **HTTP/2**.

I filtered the decrypted traffic with:

```text
http2
```

The capture showed readable HTTP/2 request headers such as:

```text
:method: GET
:scheme: https
:authority: www.consolekings.com
:path: /leaderboard?... 
```

![Decrypted HTTP/2 request headers](screenshots/03-decrypted-http2-request-headers.png)

This demonstrated that the apparent "garbled" data in a raw TLS stream was not ordinary plaintext. Once TLS was decrypted, Wireshark could interpret the underlying binary HTTP/2 frames and reconstruct their header fields.

---

## 5. HTTP/2 Response

The decrypted capture also showed the server's response to the web request.

The browser first received a:

```text
307 Temporary Redirect
```

and then established traffic with `www.consolekings.com`.

For the subsequent request, Wireshark showed:

```text
GET /
103 Early Hints
200 OK
DATA
```

The response headers also identified:

```text
server: Vercel
x-powered-by: Next.js
```

![Decrypted HTTP/2 response](screenshots/04-decrypted-http2-response-200-ok.png)

The `200 OK` response confirmed that the request succeeded. The following HTTP/2 DATA frames carried the response body.

The later connection used `216.150.1.193` rather than the `216.150.1.1` address seen in the initial DNS/TCP capture. The decrypted traffic also showed that the site redirected to the `www` hostname and was being served through Vercel infrastructure.

---

## Wireshark Techniques Used

| Technique | Purpose |
|---|---|
| `dns.qry.name == "consolekings.com"` | Isolate DNS lookups for the target |
| `ip.addr == 216.150.1.1 && tcp` | Isolate TCP traffic involving the resolved address |
| `tcp.stream eq 41` | Follow one exact TCP conversation |
| `http2` | Display decrypted HTTP/2 traffic |
| Follow TCP Stream | Reconstruct one TCP session |
| Follow TLS Stream | Inspect one TLS session |
| TLS key log file | Decrypt my own controlled Firefox TLS session |

---

## Key Findings

1. DNS resolved `consolekings.com` to an IPv4 address before the web connection was established.
2. The HTTPS connection used a standard TCP three-way handshake before TLS began.
3. TLS prevented a passive packet capture from directly reading the web application's contents.
4. Supplying authorized session secrets allowed Wireshark to decode the encrypted traffic as HTTP/2.
5. HTTP/2 exposed structured requests and responses after decryption, including `GET` requests and a successful `200 OK`.
6. The capture showed evidence that the website was served through Vercel and built with Next.js.

---

## Security Takeaways

This lab reinforced an important distinction between **network metadata** and **application content**.

Even when HTTPS encrypts the application payload, an analyst may still be able to observe connection endpoints, ports, timing, packet sizes, and some handshake information. Access to endpoint-generated TLS session secrets changes that visibility and can allow authorized troubleshooting or forensic analysis of the application traffic itself.

The exercise also demonstrated why packet analysis is largely an exercise in filtering. A live capture contains many simultaneous conversations; identifying the relevant domain, IP address, and TCP stream makes the traffic understandable.

---

## Limitations

- This was a controlled analysis of normal traffic from one device, not an investigation of malicious activity.
- DNS/TCP analysis and TLS-decryption analysis were performed in separate controlled captures.
- NAT behavior was inferred from the capture point and network design; I did not capture packets on both sides of the gateway.
- Cloud-hosted websites can use redirects and multiple edge addresses, so the IP addresses observed here should be treated as capture-specific rather than permanent.
- I intentionally did not publish the raw PCAP or TLS key log because packet captures and session secrets can contain sensitive information.

---

## What I Learned

This case gave me practical experience moving from a noisy packet capture to one specific network conversation. I practiced DNS analysis, TCP handshake identification, TLS inspection, stream filtering, and authorized TLS decryption.

Most importantly, the lab connected concepts I had previously learned separately. I could see the sequence from name resolution to connection establishment, encryption, and finally the HTTP request/response carried inside that encrypted session.

---

## Evidence Files

```text
screenshots/
├── 01-dns-resolution.png
├── 02-tcp-three-way-handshake-and-tls.png
├── 03-decrypted-http2-request-headers.png
└── 04-decrypted-http2-response-200-ok.png
```

Raw packet captures and TLS session-key files are intentionally excluded from the public repository.

---

## References

- Wireshark User's Guide
- Wireshark TLS documentation
- RFC 9113 — HTTP/2
- Vercel domain and Anycast routing documentation
