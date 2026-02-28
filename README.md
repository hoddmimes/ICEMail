## ICEMail

For the time being using the word ICE is a bit loaded. Last weekend there was a snow storm on the east cost of U.S and
the weather stations was told to not use the word ICE due to what is currently happening in U.S. However the choice of
the name is not related to the turnmoil currently taking place.

The ICE is an abbrivation for
- **I**: Interrelated
- **C**: Connectivity
- **E**: Engagement

_**Interconnectedness**_, the concept that all phenomena arise in dependence on conditions and are interconnected.
This emphasizes that every event is part of a larger web of cause and effect, giving it significance in the broader
context of life. This also in my in line with my foundational beliefs of being a _Causal Determinist_

_That was about the project name_ :smile:

---

## What is ICEMail?

ICEMail is a self-hosted, end-to-end encrypted mail system inspired by [Proton Mail](https://en.wikipedia.org/wiki/Proton_Mail),
but designed to run on your own infrastructure. The goal is straightforward: you own your mail server, you own your keys,
and no part of the system — not even the server — can read your messages.

The project is a personal endeavour started during retirement, with no commercial ambition. If it becomes useful to others,
that is a welcome bonus. It is also my first experience using AI (Claude) as a development aid — a pairing that has proven
more productive than expected. _(wounder what the last sentence came from?)_

---

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
- **Admin interface** — Browser-based administration for managing users and monitoring the IMAP server.

### ICEMail Bridge — *new development*

A lightweight IMAP proxy that runs on the **user's own machine**, not on the server. It enables any
standard IMAP/SMTP mail client to work transparently with the ICEMail encrypted infrastructure:

- **IMAP proxy** — Listens for standard IMAP or IMAPS connections from the mail client. Intercepts the
  LOGIN command and hashes the user's password with PBKDF2 before forwarding it to James, so the client
  can authenticate with its real password while the server only ever sees the hash. Incoming messages
  are decrypted on the fly using the user's PGP private key before being passed to the mail client.
- **SMTP proxy** — Optionally listens for SMTP submission from the mail client and proxies it to Postfix,
  again hashing the password in transit so the credential reaching the server is always the PBKDF2 hash.

The mail client needs no plugins and no knowledge of PGP. From its perspective it is talking to a normal
IMAP/SMTP server.

### Apache James (IMAP server) — *forked and extended*

[Apache James](https://james.apache.org/) is a mature, open-source Java mail server. In ICEMail it serves
as the IMAP store — it receives delivered mail via LMTP, stores mailboxes, and serves IMAP sessions.
James has no knowledge of the encryption; to it the messages are just data.

The fork adds two features not in the upstream project:

- **User synchronisation** — James periodically polls the ICEMail Server's `/api/users` REST endpoint to
  mirror user accounts (usernames and hashed passwords) into its own Derby database. No separate user
  administration is needed in James.
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

No Postfix source code is touched. The integration is entirely through Postfix's standard
`content_filter` and `smtpd_sasl_type = dovecot` configuration directives.

---

## Component Adaptation Summary

| Component | Origin | Adaptation |
|---|---|---|
| **ICEMail Server** | New development | 100% new — REST API, web app, after-queue filter, SASL server, user DB |
| **ICEMail Bridge** | New development | 100% new — IMAP proxy, SMTP proxy, PGP decryption, PBKDF2 login handler |
| **Apache James** | Open source fork | Two additions: user sync from ICEMail Server, WebAdmin REST API |
| **Postfix** | Standard installation | Zero code changes — integration via configuration only |

---

## Further Reading

A detailed architecture description including component internals, connection protocols, and step-by-step
flow diagrams for all key operations (account creation, login, reading mail, composing mail, mail client
setup) is available in [`doc/architecture.md`](doc/architecture.md).


## How to get it up and running.

Setting up your own mail server is not for the faint of heart. Adding the ICEMail function add an extra dimension 
of complexity. However, here is a crash instruction on 10000 feet what to think about.

- Start with getting a machine to run the solution on, I have been using a Rasberry PI model 4, with Ubunto server 24.03 
  as target machine.
- You have to install the postfix mail server and pytho3-spf and Java (use something >= 17)
- Then you need to get your self a registered public domain. You should take a look at how to use and setup DKIM, 
  DMARC and SPF that is a configuration task in DNS and postfix. Well it is possible to get everything running on a private 
   network without all mail protection setup in DNS. That what I used when developing the solution.
- I have a script deploy.sh that copy all required files over to the target machine. To be used after a successfull build.
- Also, there is a separate project required for providing the IMAP server functionality. The project is
  [IMAP-apache-james]( https://github.com/hoddmimes/IMAP-Apache-James) the project is forked from 
  [Apache James project](https://github.com/apache/james-project) and being stripped down to just include the need IMAP 
  functionality.
- That project IMAP-apache-james also contain a deploy.sh and deploy-all.sh for identifying and deploying required artefacts.
  The IMAP server is essential and required.
- In the extra directory I have placed a few files that might help you to get going
    - postfix configuration files 
    - run files for the ICEMail server, bridge and IMAP (james) server.
    - If you would like to run the servers as server there are examples how on the service defintion files.

I have a very first version of the solution up and running for testing on koxnan.com. 
You might be able to try it out on https://www.koxnan.com:8282/index.html


_That is all folk!_

