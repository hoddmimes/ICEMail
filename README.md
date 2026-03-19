## ICEMail

- Own hosted mailserver, based upon open source software, postfix, Apache-James, and developed ICE mail
- Focus on privacy, all data in the mail solution are encrypted (PGP), messages,user data in flight and persisted on disk.
- Only users can read their own mails after being transferred to their mail client machines.

# Why?
**_Why would you like to run your own mail server?_**  
The simple answer is, you do not! Unless you have close to sick desire to for spending time on a
challenging exercise and/or crazy about your privacy.

**[Just Google pros/cons](https://www.google.com/search?q=why+should+you+run+your+own+mail+server&oq=why+should+you+run+your+own+mail+server)**

_Personally, I have hosted my own mail server for over 20 years. It started off as a fun and interesting project, 
and it has continued for no particular reason! 😊 However, it hasn't always been enjoyable or appealing. 
For me this project was about learning a little bit more about how different mail components are interconnected
and just to have something to do on my so called, infinite vacation_.



## What is ICEMail?

ICEMail is a self-hosted, end-to-end encrypted mail system inspired by [Proton Mail](https://en.wikipedia.org/wiki/Proton_Mail),
but designed to run on your own infrastructure. The goal is straightforward: you own your mail server, you own your keys,
and all encrypted with your password that never leaves yor mail client — all data/mails, keys are encrypted on the server
, the server can read/see your data in clear text.

The project is a personal endeavour started during retirement, with no commercial ambition. If it becomes useful to others,
that is a welcome bonus. It is also my first experience using AI (Claude) as a development aid — a pairing that has proven
more productive than expected. _(wounder what the last sentence came from?)_

---
<div style="text-align: center;">
<img src="./doc/architecture.png" alt="Description" style="width: 60%; height: auto;">
</div>

## Core Philosophy — Encrypted Everywhere, Keys Nowhere on the Server

The central design principle is that **the server is blind**. Every message is encrypted before it enters the mailbox,
and every piece of sensitive user data is encrypted before it leaves the client. Concretely:

- **Messages at rest** — All mail stored in the IMAP server is PGP-encrypted with the recipient's public key before
  delivery. The IMAP server holds only ciphertext and has no access to any decryption key.

- **Messages in transit** — All network connections use TLS. The web interface and REST API run over HTTPS.
  IMAP access uses IMAPS (TLS). SMTP submission uses STARTTLS.

- **Passwords** — The user's password never leaves the browser or mail client in cleartext. It is hashed using
  PBKDF2 (100 000 iterations, SHA-256) client-side before being transmitted or stored. The server stores and
  compares only the hash.

- **Private keys** — Each user has a PGP key pair generated entirely in the browser at account creation. The
  private key is double-protected: first it is passphrase-protected by the user's own password (standard PGP),
  then the armored key is symmetrically encrypted again with the password using OpenPGP before being uploaded.
  The server stores an encrypted blob it cannot decrypt.

- **Decryption happens at the client** — In the web interface, decryption runs in the browser using `openpgp.js`.
  When using a standard mail client (Thunderbird, etc.) the ICEMail Bridge running on the user's own machine
  performs decryption locally before handing the message to the client. At no point does plaintext mail cross
  the server.
  
   Since all encryption, takes place in the _mail client_, standard mail clients like Outlook, Thunderbird etc. can not connect 
   and process mail as when using ordinary smtp/imap servers. Therefor there is a simple web interface has been provided 
   handling the extended encryption. However, standard mail clients can be used if connect via en [ICEMail Bridge](#icemail-bridge--new-development) 


---

## Components and Their Roles

The system is built from four components. Two are standard open-source infrastructure used without modification,
one is a fork with targeted additions, and two are written from scratch as part of this project.

### ICEMail Server — *new development*

The heart of the system. A Java 21 application built on the Javalin/Jetty framework, providing:

- **User profile database** — SQLite3 store of usernames, PBKDF2-hashed passwords, PGP public keys,
  and password-encrypted private keys. All sensitive fields are encrypted before they arrive.
- **REST API** — HTTPS endpoints for registration, login, session management, and web mail operations.
- **Web interface** — A browser-based mail client (HTML/JS) that fetches encrypted mail from James and
  decrypts it client-side using `openpgp.js`. No plaintext mail is ever served to the browser.
- **Postfix after-queue filter** — An SMTP filter that Postfix routes all inbound mail through. It looks up
  the recipient's public PGP key, encrypts the message body with AES-256 before re-injecting it back into
  Postfix for final delivery. This is where plaintext mail becomes ciphertext.
- **Dovecot SASL server** — An embedded SASL authentication service that Postfix delegates SMTP AUTH
  decisions to, allowing mail clients to submit mail using their ICEMail credentials without a separate
  user database in Postfix.
- **Postfix policy service** — A lightweight TCP policy server (port 10028) that Postfix calls after each
  successfully submitted message. It records outbound mail statistics and always passes the message through
  without interfering with delivery.
- **Admin interface** — Browser-based administration for managing users, monitoring the IMAP server, and
  viewing server statistics (registered users, logins, mail sent and received in the last 24 hours).

### ICEMail Bridge — *new development*

A lightweight IMAP proxy that runs on the **user's own machine**, not on the server. It enables any
standard IMAP/SMTP mail client to work transparently with the ICEMail encrypted infrastructure:

- **IMAP proxy** — Listens for standard IMAP or IMAPS connections from the mail client. Intercepts the
  LOGIN command and hashes the user's password with PBKDF2 before forwarding it to James, so the client
  can authenticate with its real password while the server only ever sees the hash. Incoming messages
  are decrypted on the fly using the user's PGP private key before being passed to the mail client.
- **SMTP proxy** — Optionally listens for SMTP submission from the mail client and proxies it to Postfix,
  again hashing the password in transit so the credential reaching the server is always the PBKDF2 hash.
  After each successfully delivered message the bridge automatically saves an encrypted copy to the
  sender's Sent folder on the IMAP server using the sender's own PGP public key.

The mail client needs no plugins and no knowledge of PGP. From its perspective it is talking to a normal
IMAP/SMTP server.

> **Important — disable the mail client's own "Save sent copy" setting.**
> Standard mail clients (Thunderbird, Outlook, Apple Mail, etc.) save a copy of every sent message to
> the Sent folder themselves via IMAP APPEND. That copy is **plaintext** — the client has no knowledge
> of the ICEMail PGP encryption. The ICEMail Bridge already saves an encrypted Sent copy automatically
> after every successful SMTP submission. To avoid a plaintext duplicate alongside the encrypted copy,
> you must configure your mail client to **not** save sent messages.
>
> In **Thunderbird**: Account Settings → Copies & Folders → uncheck *Place a copy in* under "When sending messages".

### Apache James (IMAP server) — *forked and extended*

[Apache James](https://james.apache.org/) is a mature, open-source Java mail server. In ICEMail it serves
as the IMAP store — it receives delivered mail via LMTP, stores mailboxes, and serves IMAP sessions.
James has no knowledge of the encryption; to it the messages are just data.

The fork adds two features not in the upstream project:

- **User synchronisation** — James polls the ICEMail Server at startup to mirror user accounts
  (usernames and hashed passwords) into its own Derby database. The sync first fetches the admin
  password from the `/api/admin` endpoint (IP-allowlisted), then uses HTTP Basic Auth to call
  `/admin/users` (session or Basic Auth protected). No separate user administration is needed in James.
- **WebAdmin REST API** — An embedded admin API (port 8000, bound to localhost) that the ICEMail Server
  proxies to the browser admin interface, exposing mailbox statistics, queue inspection, and dead-letter
  management.

Everything else — IMAP protocol handling, mail storage (Derby + Lucene), LMTP delivery acceptance — is
standard Apache James.

### Postfix (MTA) — *standard, unmodified*

[Postfix](https://www.postfix.org/) is used as the Mail Transfer Agent with no code changes whatsoever.
It is configured (not coded) to integrate with the ICEMail ecosystem:

- Receives inbound mail from the internet on port 25 (standard MX).
- Routes all inbound mail through the ICEMail Server after-queue filter on port 10026 before delivery.
- Accepts re-injected, encrypted mail from the filter on port 10027 and delivers it to James via LMTP on port 24.
- Accepts authenticated SMTP submission on port 587 (STARTTLS), delegating credential validation to the
  ICEMail Server's SASL server on port 12345.
- After each successfully submitted message, calls the ICEMail Server's **Postfix policy service** on
  port 10028 (via `smtpd_end_of_data_restrictions = check_policy_service`) to record sent-mail statistics.
  The policy service always responds `dunno` — it never rejects mail.

No Postfix source code is touched. The integration is entirely through Postfix's standard
`content_filter`, `smtpd_sasl_type = dovecot`, and `smtpd_end_of_data_restrictions` configuration directives.

---

## Component Adaptation Summary

| Component | Origin | Adaptation |
|---|---|---|
| **ICEMail Server** | New development | 100% new — REST API, web app, after-queue filter, SASL server, user DB |
| **ICEMail Bridge** | New development | 100% new — IMAP proxy, SMTP proxy, PGP decryption, PBKDF2 login handler |
| **Apache James** | Open source fork | Two additions: user sync from ICEMail Server, WebAdmin REST API |
| **Postfix** | Standard installation | Zero code changes — integration via configuration only |

---

## Encryption in Practice

ICEMail applies encryption at multiple layers, covering both transport security and message confidentiality.

### Transport Encryption (SMTP between servers)

When Postfix exchanges mail with other servers on the internet, TLS is used **opportunistically**. Postfix will attempt to establish a TLS-encrypted connection for both inbound and outbound SMTP, but will fall back to plaintext if the remote server does not support TLS. This is standard behaviour for internet mail and provides best-effort transport confidentiality without breaking compatibility with older or misconfigured servers.

### End-to-End Encryption for Local Users

All mail delivered to a user whose mailbox is hosted on the ICEMail server is encrypted **before** it is stored. The ICEMail after-queue filter intercepts every inbound message after Postfix accepts it, looks up the recipient's PGP public key, and encrypts the message body using AES-256 with the session key wrapped in the recipient's public key. Only the ciphertext is delivered to the IMAP store (Apache James). Neither the server nor anyone with access to the server's filesystem or database can read the message content.

**All messages persisted in the ICEMail IMAP server are PGP-encrypted — without exception.** There is no plaintext mail at rest anywhere in the system.

This encryption is applied regardless of where the mail originates — whether from another ICEMail user, an external sender, or a mailing list. Sent mail copies stored in the Sent folder are also encrypted: the ICEMail Bridge encrypts the outgoing message with the **sender's own PGP public key** before appending it to the Sent folder, so Sent mail is as protected as received mail. (Mail clients must be configured not to save their own plaintext Sent copy — see the Bridge section above.)

### Mail to External Recipients

Mail sent from ICEMail to recipients on **external mail servers** is delivered as ordinary internet mail and is **not end-to-end encrypted by default**. There is no general mechanism to obtain an external recipient's PGP key automatically, and external mail servers are not expected to accept PGP-encrypted payloads. Transport-level TLS is still applied where the receiving server supports it.

### Encrypted Mail to External Recipients via Link

For situations where sensitive content must be sent to an external recipient, the web mail compose page provides an optional password-based encryption feature. When used:

1. The message body is encrypted in the browser using AES with a user-chosen password.
2. The encrypted payload is stored temporarily on the ICEMail server.
3. A plain-text mail is sent to the external recipient containing a link to a decryption page on the ICEMail web interface.
4. The recipient opens the link, enters the agreed password, and the message is decrypted and displayed entirely in their browser.

The ICEMail server never sees the password or the plaintext — decryption happens client-side in the recipient's browser. The shared password must be exchanged with the recipient through a separate, trusted channel (phone call, Signal, etc.).

### Encrypted Mail via Standard Mail Clients (Mailbridge)

Users who prefer to use a standard mail client (Apple Mail, Thunderbird, or any IMAP/SMTP client) instead of the web interface can still send password-encrypted mail to external or internal recipients, via the ICEMail mailbridge.

To trigger encryption, prefix the subject line with `encrypt:<password>:` followed by the intended subject:

```
encrypt:MyPassword:Hello, this is the real subject
```

The mailbridge intercepts the outgoing message during SMTP submission and:

1. Extracts the password and the real subject from the subject line.
2. Decodes the message body (handling multipart, quoted-printable, and base64 as needed).
3. Encrypts the body using AES-256-GCM with PBKDF2 key derivation — the same algorithm used by the web compose page.
4. Stores the encrypted payload on the ICEMail server and replaces the outgoing mail with a notification containing a link to the decryption page.
5. Rewrites the subject to remove the `encrypt:<password>:` prefix before the mail leaves the server, so recipients only see the intended subject.

Replies are also supported — the `Re:` prefix is preserved correctly:

```
Re: encrypt:MyPassword:Original Subject
```

becomes a reply with subject `Re: Original Subject`.

**Rules for the password:**
- Must be at least 8 characters.
- Must not contain the `:` character (it is used as the delimiter).
- Must be shared with the recipient through a separate trusted channel (phone, Signal, etc.) — the server never sees the password.

The decryption happens entirely client-side in the recipient's browser, on the same page used by the web compose feature. From the recipient's perspective there is no difference between a mail encrypted via the web interface and one encrypted via a standard mail client.

### General-Purpose AES Encryption Page

The ICEMail web interface includes a standalone, publicly accessible page for encrypting and decrypting arbitrary text using AES. This page is available to anyone, with or without an ICEMail account, and can be used independently of the mail system — for example, to encrypt a text snippet before sharing it through any channel, or to decrypt content received from someone using the same page.

---

## Further Reading

A detailed architecture description including component internals, connection protocols, and step-by-step
flow diagrams for all key operations (account creation, login, reading mail, composing mail, mail client
setup) is available in [`doc/architecture.md`](doc/architecture.md).


## Installation

Setting up your own mail server is not for the faint of heart. Adding the ICEMail function add an extra dimension 
of complexity. However, here is a crash instruction on 10000 feet what to think about.

The most pragmatic way to get the solution up and running on a Linux is to install the components 
using the provided [makeself](https://gcore.com/learning/how-to-make-file-executable-in-linux) run files

They will install and setup what you need for getting a jump start.

- ice-server ice-server-installer-1.0.run
- ice-bridge ice-bridge-installer-1.0.run
- ice-imap   ice-imap-installer-1.0.run

**Postfix Setup**  
Maybe the most challenging part is the postfix setup. Besides the ordinary postfix configurations like 
[DNS](https://support.dnsmadeeasy.com/hc/en-us/articles/34327241485083-MX-Record), 
[DKIM](https://easydmarc.com/blog/how-to-configure-dkim-opendkim-with-postfix/),
[DMARC](https://wiki.archlinux.org/title/OpenDMARC),
[SPF](https://wiki.gentoo.org/wiki/Postfix/SPF) and SPAM filters that all are more or less mandatory.
There are a few mandatory configurations for ICE mail. These are listed below.  

**master.cf**

<u>SASL Authentication via ICEMail</u>

Postfix delegates SMTP authentication to the ICEMail server's built-in Dovecot-compatible SASL service rather than to a real      
Dovecot instance. The ICEMail server listens on a plain TCP socket on loopback.
```
smtpd_sasl_auth_enable = yes                                                                                                      
smtpd_sasl_type = dovecot
smtpd_sasl_path = inet:127.0.0.1:12345
```

<u>Virtual Mailbox Delivery via LMTP to ICE Imap</u>

Incoming mail for koxnan.com is not delivered locally by Postfix. Instead it is handed off to the ICEMail IMAP server (Apache     
James) via LMTP. The domain must not be in mydestination — if it were, Postfix would attempt local delivery instead.
```
virtual_transport = lmtp:inet:127.0.0.1:24                
virtual_mailbox_domains = <mail domain>
```

<u>PGP Encryption Content Filter</u>

After a message is accepted, Postfix passes it through the ICEMail encryption filter (PostfixAfterQueueFilter) before final       
delivery. The filter encrypts the message body with the recipient's PGP public key and re-injects the encrypted message back into
Postfix. The policy service on port 10028 is used for end-of-data checks.
```
content_filter = encryptor:[127.0.0.1]:10026
smtpd_end_of_data_restrictions = check_policy_service inet:127.0.0.1:10028
```

The flow for inbound mail is:

▎ Incoming SMTP → Postfix → encryptor filter (:10026) → re-injected encrypted mail → LMTP → Apache James (:24)

<u>Policy service (port 10028)</u>

Port 10028 is a standalone TCP listener started by the ICEMail server (PostfixPolicyServer). Postfix calls it as a policy service
at end-of-data via main.cf:
```
smtpd_end_of_data_restrictions = check_policy_service inet:127.0.0.1:10028
```

**master.cf**

<u>Submission port for ICEMail bridge (port 1587)</u>

The standard submission port 587, if you run the bridge on the same host as the ice-server, you should let the bridge use 
port 587 and havee postfix to listening on port 1587. This is the port the ICEMail bridge's SMTP proxy connects to when  
relaying outbound mail from clients. TLS and SASL authentication are enforced, and only authenticated clients or local networks   
are permitted
```
587 inet n       -       y       -       -       smtpd                                                                           
-o syslog_name=postfix/submission                                                                                               
-o smtpd_tls_security_level=encrypt                                                                                             
-o smtpd_sasl_auth_enable=yes                                                                                                   
-o smtpd_tls_auth_only=yes                                                                                                      
-o smtpd_client_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
```

<u>PGP encryption filter service (encryptor)</u>

This defines the encryptor content filter referenced in main.cf. Postfix connects to the ICEMail PostfixAfterQueueFilter on port  
10026 using the smtp transport. MIME conversion is disabled to prevent Postfix from altering the message body before the filter
sees it. TLS is disabled on this loopback connection since it is internal.
```
encryptor unix  -      -       n       -       10      smtp
-o smtp_send_xforward_command=yes                                                                                               
-o disable_mime_output_conversion=yes                                                                                           
-o smtp_tls_security_level=none                                                                                                 
-o smtp_tls_wrappermode=no
```

<u>Re-injection listener (port 10027)</u>

After the PostfixAfterQueueFilter has encrypted the message body, it re-injects the encrypted mail 
back into Postfix on port 10027. This listener is configured to bypass all further filtering — no content filter, no address mappings, no header/body checks
       — so the already-encrypted message goes straight through to LMTP delivery to IMAP server.
```
127.0.0.1:10027 inet n  -       n       -       -       smtpd
-o content_filter=                                                                                                              
-o receive_override_options=no_address_mappings,no_unknown_recipient_checks,no_header_body_checks                               
-o local_recipient_maps=                                                                                                        
-o relay_recipient_maps=                                                                                                        
-o smtpd_relay_restrictions=permit_mynetworks,reject
```

- In the project _extra_ directory I have placed a few files that might help you to get going
    - postfix configuration files 

---

## Project Name

The ICE is an abbreviation for
- **I**: Interrelated
- **C**: Connectivity
- **E**: Engagement

_**Interconnectedness**_, the concept that all phenomena arise in dependence on conditions and are interconnected.
This emphasizes that every event is part of a larger web of cause and effect, giving it significance in the broader
context of life. This also in my in line with my foundational beliefs of being a _Causal Determinist_

_That was about the project name_ :smile:

---

I have a very first version of the solution up and running for testing on koxnan.com. 
You might be able to try it out on https://www.koxnan.com/index.html




_That is all folk!_

