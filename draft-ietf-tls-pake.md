---
title: A Password Authenticated Key Exchange Extension for TLS 1.3
abbrev: TLS 1.3 PAKE
docname: draft-ietf-tls-pake-latest
submissiontype: IETF
category: info

ipr: trust200902
area: Security
workgroup: "Transport Layer Security"
venue:
    group: "Transport Layer Security"
    type: "Working Group"
    mail: "tls@ietf.org"
    arch: "https://mailarchive.ietf.org/arch/browse/tls/"
    github: "tlswg/tls-pake"
    latest: "https://tlswg.org/tls-pake/draft-ietf-tls-pake.html"
v: 0
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: L. Bauman
    name: Laura Bauman
    organization: Apple, Inc.
    email: l_bauman@apple.com
 - ins: "D. Benjamin"
   name: "David Benjamin"
   organization: "Google LLC"
   email: davidben@google.com
 - ins: S. Menon
   name: Samir Menon
   organization: Apple, Inc.
   email: samir_menon@apple.com
 - ins: C. A. Wood
   name: Christopher A. Wood
   organization: Apple, Inc.
   email: caw@heapingbits.net

normative:
  PQPAKE:
    title: "Hybrid Post-Quantum Password Authenticated Key Exchange"
    target: https://datatracker.ietf.org/doc/draft-vos-cfrg-pqpake/
    date: 2026
    author:
      - ins: J. Vos
      - ins: C. A. Wood
    seriesinfo:
      Internet-Draft: draft-vos-cfrg-pqpake-latest
  XWING:
    title: "X-Wing: The Hybrid KEM You've Been Looking For"
    target: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
    date: 2024
    author:
      - ins: D. Connolly
      - ins: P. Schwabe
      - ins: B. Westerbaan
    seriesinfo:
      Internet-Draft: draft-connolly-cfrg-xwing-kem-latest

informative:
  ARGON2:
    title: "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications"
    seriesinfo:
      RFC: 9106
    date: 2022


--- abstract

The pre-shared key mechanism available in TLS 1.3 is not suitable
for usage with low-entropy keys, such as passwords entered by users.
This document describes an extension that enables the use of
password-authenticated key exchange protocols with TLS 1.3.


--- middle

# Introduction

DISCLAIMER: Much of this text is copied from {{?FIRST-DRAFT=I-D.barnes-tls-pake}}
and is in the process of being updated. This is a work-in-progress draft and has
not yet seen significant security analysis. See {{security}} and {{spake2plus-sec}}
for more information.

In some applications, it is desirable to enable a client and server
to authenticate to one another using a low-entropy pre-shared value,
such as a user-entered password.

In prior versions of TLS, this functionality has been provided by
the integration of the Secure Remote Password PAKE protocol (SRP)
{{?RFC5054}}. The specific SRP integration described in RFC 5054
does not immediately extend to TLS 1.3 because it relies on the
Client Key Exchange and Server Key Exchange messages, which no
longer exist in 1.3.

TLS 1.3 itself provides a mechanism for authentication with
pre-shared keys (PSKs). However, PSKs used with this protocol need
to be "full-entropy", because the binder values used for
authentication can be used to mount a dictionary attack on the PSK.
So while the TLS 1.3 PSK mechanism is suitable for the session
resumption cases for which it is specified, it cannot be used when
the client and server share only a low-entropy secret.

Enabling TLS to address this use case effectively requires the TLS
handshake to execute a password-authenticated key establishment
(PAKE) protocol. This document describes a TLS extension `pake`
that can carry data necessary to execute a PAKE.

This extension is generic, in that it can be used to carry key
exchange information for multiple different PAKEs. We assume that
prior to the TLS handshake the client and server will both have
knowledge of the password or PAKE-specific values derived from the
password (e.g. augmented PAKEs only require one party to know the
actual password). The choice of PAKE and any required parameters will
be explicitly specified using IANA assigned values.
This document defines concrete protocols for executing the
SPAKE2+ {{!RFC9383}}, CPACE {{!CPACE=I-D.irtf-cfrg-cpace}},
OQUAKE {{PQPAKE}}, and
OQUAKE+ {{PQPAKE}} PAKE protocols.

# Terminology

{::boilerplate bcp14-tagged}

The mechanisms described in this document also apply to DTLS 1.3
{{!RFC9147}}, but for brevity, we will refer only to TLS
throughout.

# Setup

In order to use the extension specified in this document, a TLS client
and server need to have pre-provisioned a password (or derived values
as described by the desired PAKE protocol(s)). The details of this
pre-provisioned information are specific to each PAKE algorithm and
are not specified here.

Servers will of course have multiple instances of this configuration
information for different clients. Clients may also have multiple
identities, even within a given server.

# PAKE Protocol Classification

This specification defines support for two classes of PAKE protocols:

Internal PAKEs integrate directly into the TLS handshake, completing authentication
within two messages (ClientHello and ServerHello). These PAKEs execute their protocol
messages within the `pake` extension and derive shared secrets that feed into the TLS
key schedule.

External PAKEs require out-of-band execution prior to TLS connection establishment.
These PAKEs complete their protocol exchange outside of TLS and import their derived
secrets as PSKs using External PSK Import {{?RFC9258}}.

The following sections describe both approaches in detail.

# Internal PAKE Integration in TLS

This section describes how Internal PAKE protocols are integrated and executed
within the TLS handshake using the `pake` extension. Internal PAKEs complete their
authentication exchange within two messages (ClientHello and ServerHello) and integrate
their derived secrets directly into the TLS key schedule.

For External PAKEs that execute out-of-band prior to TLS connection establishment,
see {{external-pakes}}.

## Client Behavior

To offer support for a PAKE protocol, the client sends a `pake` extension
in the ClientHello carrying a `PAKEClientHello` value:

~~~
enum {
    pake(0xTODO), (65535)
} ExtensionType;
~~~

The payload of the client extension has the following `PAKEClientHello`
structure:

~~~~~
enum {
    SPAKE2PLUS_V1 (0xXXXX),
    CPACE_X25519_SHA512 (0xXXXX),
    OQUAKE_V1 (0xXXXX),
    OQUAKE_PLUS_V1 (0xXXXX),
} PAKEScheme;

struct {
    PAKEScheme   pake_scheme;
    opaque      pake_message<1..2^16-1>;
} PAKEShare;

struct {
    opaque    client_identity<0..2^16-1>;
    opaque    server_identity<0..2^16-1>;
    PAKEShare client_shares<0..2^16-1>;
} PAKEClientHello;
~~~~~

The `PAKEClientHello` structure consists of an identity pair under which the
client can authenticate alongside a list of PAKE algorithms and the
client's first message for each underlying PAKE protocol.
Concretely, these structure fields are defined as follows:

client_shares
: A list of PAKEShare values, each one with a distinct PAKEScheme algorithm.

client_identity
: The client identity used for the PAKE. It may be empty.

server_identity
: The server identity used for the PAKE. It may be empty.

pake_scheme
: The 2-byte identifier of the PAKE algorithm.

pake_message
: The client PAKE message used to initialize the protocol.

The client and server identity fields are common to all PAKEShares to prevent
client enumeration attacks; see {{security}}.

The `PAKEScheme` field in the `PAKEShare` allows implementations to
support multiple PAKEs and negotiate which to use in the context of
the handshake. For instance, if a client knows a password but not which
PAKE the server supports it could send corresponding PAKEShares for each
PAKE. If the client sends multiple PAKEShare values, then they MUST
be sorted in monotonically increasing order by the NamedPAKE value. Moreover,
the client MUST NOT send more than one PAKEShare with the same NamedPAKE value.

{{Section 9.2 of !TLS13=RFC8446}} specifies that a valid ClientHello
must include either a `pre_shared_key` extension or both
a `signature_algorithms` and `supported_groups` extension. With the
addition of the `pake` extension specified here, the new requirement
is that a valid ClientHello must satisfy at least one of the
following options:

* includes a `pre_shared_key` extension
* includes `signature_algorithms`, `supported_groups`, and `key_share`  extensions
* includes `pake`, `supported_groups`, and `key_share` extensions

If a client sends the `pake` extension, then it MUST also send a `supported_groups` and
`key_share` extension. Like PSK-based authentication in psk_dhe_ke mode as defined in
{{Section 4.2.0 of !TLS13=RFC8446}}, authentication with the `pake` extension
is always combined with the normal TLS key exchange mechanism. See {{key-sched-mods}} for details.

Combining the `pake` extension with the normal TLS key exchange mechanism
using a hybrid or PQ key agreement protects against Harvest Now Decrypt
Later Attacks where traffic recorded today may be decrypted by a Cryptographically
Relevant Quantum Computer (CRQC) in the future. This protection covers the
resulting *application traffic* regardless of which PAKEScheme is negotiated.
It does not, by itself, protect the *password*: if the negotiated PAKEScheme is
purely classical (e.g., SPAKE2+ or CPace), a future CRQC that breaks the
scheme's underlying classical assumption can still retroactively recover the
password from the harvested `pake` extension messages, independent of whether
the surrounding TLS key exchange was hybrid or PQ. Deployments concerned with
retroactive password recovery, as opposed to only traffic confidentiality,
should select a post-quantum PAKEScheme, such as OQUAKE, OQUAKE+, or
CPaceOQUAKE+; see the Security Considerations of {{PQPAKE}} for a detailed
treatment of this distinction.

A client which sends both a `pake` and `signature_algorithms` extension indicates the client
requires both PAKE authentication and standard server certificate authentication.

The client MAY also send a `pre_shared_key` extension along with the `pake` extension,
to allow the server to choose an authentication mode.

The server identity value provided in the PAKEClientHello structure
are disjoint from that which the client may provide in the
ServerNameIndication (SNI) field.

## Server Behavior

If a server receives a ClientHello with a `pake` extension, but without both
a`supported_group` and `key_share` extension it MUST abort the connection with a
"missing_extension" alert.

If a server receives a ClientHello with a `pake` extension and `pre_shared_key`
extension then it must choose an authentication mechanism. In cases where client
enumeration is a risk, servers SHOULD NOT inspect the offered `client_identity` fields
in the `pake` extension when deciding between PAKE or PSK authentication since this
could be used as an client enumeration tool.

A server that receives a `pake` extension examines its contents to determine
if it is well-formed. In particular, if the list of PAKEShare values is not
sorted in monotonically increasing order by PAKEScheme values, or if there are
duplicate PAKEScheme entries in this list, the server aborts the handshake with
an "illegal_parameter" alert.

If the list of PAKEShare values is well-formed, the server then scans the list
of PAKEShare values to determine if there is one corresponding to a server
supported PAKEScheme. If the server does not support any of the offered PAKESchemes
in the client PAKEShares then the server MUST abort the protocol
with an "illegal_parameter" alert.

If the server has a PAKEScheme in common with the client then the server uses
the client_identity and server_identity alongside its local database of PAKE
registration information to determine if the request corresponds to a legitimate
client registration record. If one does not
exist, the server MAY simulate a PAKE response as described in {{simulation}}.
Simulating a response prevents client enumeration attacks on the server's
PAKE database; see {{security}}.

If there exists a valid PAKE registration, the server indicates its selection
by including a `pake` extension in its ServerHello. The content of this extension
is a `PAKEServerHello` value, specifying the PAKE the server has selected, and the
server's first message in the PAKE protocol. The format of this structure is as follows:

~~~~~
struct {
    PAKEShare server_share;
} PAKEServerHello;
~~~~~

The server_share value of this structure is a `PAKEShare`, which echoes
back the PAKE algorithm chosen and the server's PAKE message generated
in response to the client's PAKE message.

If a server uses PAKE authentication, then it MUST NOT send an
extension of type `pre_shared_key`, or `early_data`.

Use of PAKE authentication MAY be used with
certificate-based authentication of both clients and servers.
If use of a PAKE is negotiated and the client included the `signature_algorithms` extension,
then servers MUST include Certificate and CertificateVerify messages in the handshake.
The server MAY send a CertificateRequest for client certificate authentication.
See {{security}} for a discussion on different security considerations
depending on if certificates are used or not.

## Key Schedule Modifications {#key-sched-mods}

When the client and server agree on a PAKE to use, a shared secret derived
from the PAKE protocol is concatenated with the regular `ECDH(E)`
input and used as part of the `ECDH(E)` input to the TLS 1.3
key schedule. Details for the shared secret computation are left to the
specific PAKE algorithm. See {{spake2plus}} and {{cpace}} for information about how
the SPAKE2+ and CPace variants operate, respectively.

As with client authentication via certificates, the server has not
authenticated the client until after it has received the client's
Finished message. When a server negotiates the use of this
mechanism for authentication, it SHOULD NOT send application data
before it has received the client's Finished message, as it would
otherwise be sending data to an unauthenticated client.

## Server Simulation {#simulation}

To simulate a fake PAKE response, the server does the following:

* Select a PAKEScheme supported by the client and server, as normal.
* Include the `pake` extension in its ServerHello, containing a PAKEShare value with
the selected PAKEScheme and corresponding `pake_message`. To generate the `pake_message`
for this `PAKEShare` value, the server selects a value uniformly at random from
the set of possible values of the PAKE algorithm shares.
* Perform the rest of the protocol as normal.

Because the server's share was selected uniformly at random, the server will reject
the client's Finished message with overwhelming probability.

A server that performs the simulation of the protocol acts only
as an all-or-nothing oracle for whether a given (identity, password) pair
is correct. If an attacker does not supply a correct pair, they do not learn
anything beyond this fact.

# Internal PAKE Protocol Specifications {#internal-pake-protocols}

## Requirements for Internal PAKEs

In order to be usable as Internal PAKEs with the `pake` extension, a PAKE protocol
must specify some syntax for its messages, and the PAKE protocol
MUST produce a shared secret in exactly two messages carried in the ClientHello
and ServerHello. Internal PAKEs complete their authentication exchange within the
TLS handshake and cannot require additional message rounds.

In addition, to be compatible with the security requirements of TLS
1.3, Internal PAKE protocols defined for use with TLS 1.3 MUST provide
forward secrecy and MUST be able to achieve key confirmation via TLS 1.3
Finished messages.

A specification describing the use of a particular Internal PAKE protocol with
TLS must provide the following details:

* A `PAKEScheme` registered value indicating pre-provisioned parameters;
* Content of the `pake_message` field in a ClientHello;
* Content of the `pake_message` field in a ServerHello;
* How the PAKE protocol is executed based on those messages; and
* How the outputs of the PAKE protocol are used to create the PAKE portion of the`(EC)DHE` input to the TLS key schedule.

Several current PAKE protocols satisfy these requirements for Internal PAKE usage,
for example:

* CPace {{!CPACE=I-D.irtf-cfrg-cpace}}
* SPAKE2+ (described in {{spake2plus}}) {{!RFC9383}}
* OPAQUE {{?OPAQUE=I-D.irtf-cfrg-opaque}}
* OQUAKE (described in {{oquake}}) {{PQPAKE}}
* OQUAKE+ (described in {{oquakeplus}}) {{PQPAKE}}

## SPAKE2+ Integration {#spake2plus}

This section describes the SPAKE2+ instantiation of the `pake` extension for TLS.
The SPAKE2+ protocol is described in {{!SPAKE2PLUS=RFC9383}}.
{{spake2plus-setup}} describes the setup required before the protocol runs,
and {{spake2plus-run}} describes the protocol execution in TLS.

### Protocol Setup {#spake2plus-setup}

The TLS client and server roles map to the `Prover` and `Verifier` roles in the
SPAKE2+ specification, respectively. Clients are configured with a client
identity, server identity, and password verifier (w0 and w1 according to {{SPAKE2PLUS}}).
Similarly, servers are configured with a list of client identity, server identity,
and password registration values (w0 and L according to {{SPAKE2PLUS}}). Servers
use this list when completing the SPAKE2+ protocol. The values for the password
verifiers and registration records (w0, w1, and L) are not specified here; see
{{Section 3.2 of SPAKE2PLUS}} for more information.

The PAKEScheme value for SPAKE2+ fully defines the parameters associated with
the protocol, including the prime-order group `G`, cryptographic hash function `Hash`,
key derivation function `KDF`, and message authentication code `MAC`. Additionally,
the PAKEScheme value for SPAKE2+ fully defines the constants for M and N
as needed for the protocol; see {{Section 4 of SPAKE2PLUS}}.

### Protocol Execution {#spake2plus-run}

The content of one PAKEShare value in the PAKEClientHello structure consists
of the PAKEScheme value `SPAKE2PLUS_V1` and the value `shareP` as computed in
{{Section 3.3 of SPAKE2PLUS}}.

The content of the server PAKEShare value in the PAKEServerHello structure
consists of the PAKEScheme value `SPAKE2PLUS_V1` and the value `shareV || confirmV`,
i.e., `shareV` and `confirmV` concatenated, as computed in {{Section 3.3 of SPAKE2PLUS}}.

Given `shareP` and `shareV`, the client and server can then both compute
K_main, the root secret in the protocol as described in {{Section 3.4 of SPAKE2PLUS}}.
The "Context" value for SPAKE2+ is equal to `tls || application_context` where
`application_context` is either an empty string or a string that may be specified by
the protocol using tls to include additional context in the protocol transcript.
See {{Section 3 of SPAKE2PLUS}}. The rest of
the values needed for the transcript derivation are as configured in {{spake2plus-setup}},
exchanged over the wire, or computed by client and server.

Using `K_main`, the client and server both compute `K_shared` which is combined with the
`(EC)DHE` shared secret as input to the TLS 1.3 key schedule, where the (EC)DHE shared
secret is as specified in {{Section 7.1 of !TLS13=RFC8446}} or as the `concatenated_shared_secret`
as specified in {{Section 3.3 of !I-D.ietf-tls-hybrid-design}}. Specifically, `K_shared || (EC)DHE` is used
as the `(EC)DHE` input to the key schedule in {{Section 7.1 of !TLS13=RFC8446}}, as shown below.

~~~
                                    0
                                    |
                                    v
                        0 ->  HKDF-Extract = Early Secret
                                    |
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    |
                                    v
                              Derive-Secret(., "derived", "")
                                    |
                                    v
                K_shared || (EC)DHE -> HKDF-Extract = Handshake Secret
                ^^^^^^^^^^^         |
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    |
                                    v
                              Derive-Secret(., "derived", "")
                                    |
                                    v
                         0 -> HKDF-Extract = Master Secret
                                    |
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
~~~

Note that the server does compute and send confirmV as defined in {{Section 3.4 of SPAKE2PLUS}}
since it can do so within the structure of the TLS 1.3 handshake and the client MUST verify it.
If verification of confirmV fails, clients SHOULD abort the handshake with a "decrypt_error" alert.
The client and server do not additionally compute or verify confirmP
as described in {{Section 3.4 of SPAKE2PLUS}}.
See {{spake2plus-sec}} for more information about the safety of this approach.

## CPace Integration {#cpace}

This section describes the CPace instantiation of the `pake` extension for TLS.
The CPace protocol is described in {{!CPACE=I-D.irtf-cfrg-cpace}}.
{{cpace-setup}} describes the setup required before the protocol runs, and
{{cpace-run}} describes the protocol execution in TLS.

### Protocol Setup {#cpace-setup}

The TLS client and server roles map to the 'initiator' and 'responder' roles in
the CPace specification, respectively. The client and server must share a
password-related string (PRS). The associated data for both parties (`ADa` and
`ADb`) is unused. The client and server may optionally be configured with party
identification strings, a channel identifier, and/or a session identifier, as
described in {{Section 3.1 of !CPACE=I-D.irtf-cfrg-cpace}}.

The PAKEScheme value for CPace specifies a cipher suite for the protocol,
consisting of a group environment `G` and cryptographic hash function `H`.

### Protocol Execution {#cpace-run}

The content of one PAKEShare value in the PAKEClientHello structure consists of
the PAKEScheme value `CPACE_X25519_SHA512` and the value `Ya` as computed in
{{Section 6.2 of !CPACE=I-D.irtf-cfrg-cpace}}.

The content of the server PAKEShare value in the PAKEServerHello structure
consists of the PAKEScheme value `CPACE_X25519_SHA512` and the value `Yb` as
computed in {{Section 6.2 of !CPACE=I-D.irtf-cfrg-cpace}}.

Given `Ya` and `Yb`, the client and server can then both compute `ISK`, the main output
secret of the protocol as described in {{Section 6.2 of !CPACE=I-D.irtf-cfrg-cpace}}.
The various optional CPace inputs (party identification strings, channel
identifiers, and session identifiers) may be specified by the application, and
will contribute to the derivation of `ISK`.

The client and server both combine `ISK` with the `(EC)DHE` shared secret as
input to the TLS 1.3 key schedule, where the (EC)DHE shared secret is as
specified in {{Section 7.1 of !TLS13=RFC8446}} or as the
`concatenated_shared_secret` as specified in {{Section 3.3 of !I-D.ietf-tls-hybrid-design}}.
Specifically, `ISK || (EC)DHE` is used as the `(EC)DHE` input to the key
schedule in {{Section 7.1 of !TLS13=RFC8446}}, as shown above in {{spake2plus-run}}.

## OQUAKE Integration {#oquake}

This section describes the OQUAKE instantiation of the `pake` extension for TLS.
The OQUAKE protocol is a post-quantum symmetric PAKE described in {{PQPAKE}}.
{{oquake-setup}} describes the setup required before the protocol runs, and
{{oquake-run}} describes the protocol execution in TLS.

### Protocol Setup {#oquake-setup}

The TLS client and server roles map to the 'initiator' and 'responder' roles in
the OQUAKE specification, respectively. The client and server must share a
password-related string (PRS). The client and server may optionally be configured
with a session identifier and client and server identifiers, as described in
{{Section 8.2 of PQPAKE}}.

The PAKEScheme value for OQUAKE specifies the BUA-sKEM instance and KDF used
by the protocol.

### Protocol Execution {#oquake-run}

The content of one PAKEShare value in the PAKEClientHello structure consists of
the PAKEScheme value `OQUAKE_V1` and the output message from `OQUAKE.Init` as
specified in {{Section 8.2.1 of PQPAKE}}.

The content of the server PAKEShare value in the PAKEServerHello structure
consists of the PAKEScheme value `OQUAKE_V1` and the output message from
`OQUAKE.Respond` as specified in {{Section 8.2.2 of PQPAKE}}.

Given these messages, the client runs `OQUAKE.Finish` to derive the session key `SK`.
The OQUAKE response message includes a key confirmation value `h`. The client
MUST verify this value as part of `OQUAKE.Finish`. If verification fails,
clients SHOULD abort the handshake with a "decrypt_error" alert.

The client and server both combine `SK` with the `(EC)DHE` shared secret as
input to the TLS 1.3 key schedule, where the (EC)DHE shared secret is as
specified in {{Section 7.1 of !TLS13=RFC8446}} or as the
`concatenated_shared_secret` as specified in {{Section 3.3 of !I-D.ietf-tls-hybrid-design}}.
Specifically, `SK || (EC)DHE` is used as the `(EC)DHE` input to the key
schedule in {{Section 7.1 of !TLS13=RFC8446}}, as shown above in {{spake2plus-run}}.

The OQUAKE `context` parameter is set to `None` for standalone use.
The OQUAKE `sid` parameter SHOULD be left empty, relying on the TLS
transcript binding via Finished messages for session uniqueness.
Client-to-server key confirmation is provided via TLS 1.3 Finished messages.

## OQUAKE+ Integration {#oquakeplus}

This section describes the OQUAKE+ instantiation of the `pake` extension for TLS.
OQUAKE+ is a post-quantum asymmetric PAKE (aPAKE) described in {{PQPAKE}}.
{{oquakeplus-setup}} describes the setup required before the protocol runs, and
{{oquakeplus-run}} describes the protocol execution in TLS.

### Protocol Setup {#oquakeplus-setup}

The TLS client and server roles map to the 'initiator' and 'responder' roles in
the OQUAKE+ specification, respectively. Clients are configured with a client
identity, server identity, password-related string (PRS), and salt. Clients use
these to derive a verifier and seed via `GenVerifierMaterial` as described in
{{Section 9.1.1 of PQPAKE}}.

Similarly, servers are configured with a list of client identity, server identity,
verifier, public key (pk), and salt values. Servers use the verifier and public key
when completing the OQUAKE+ protocol. The values for the verifier and public key
are generated using `GenVerifiers` as specified in {{Section 9.1.1 of PQPAKE}}.

The PAKEScheme value for OQUAKE+ specifies the BUA-sKEM instance, KEM instance,
KDF, and KSF used by the protocol.

### Protocol Execution {#oquakeplus-run}

The content of one PAKEShare value in the PAKEClientHello structure consists of
the PAKEScheme value `OQUAKE_PLUS_V1` and the output message from `OQUAKE+.Init`
as specified in {{Section 9.2.1 of PQPAKE}}, using the verifier as the
password-related string.

The content of the server PAKEShare value in the PAKEServerHello structure
consists of the PAKEScheme value `OQUAKE_PLUS_V1` and the output message from
`OQUAKE+.Respond` as specified in {{Section 9.2.2 of PQPAKE}}, using the verifier
as the password-related string and the client's registered public key.

Upon receiving the client's PAKEShare `pake_message` (denoted `init_msg`),
the server produces the response message and derives its shared secret by
invoking `OQUAKE+.Respond`, as specified in {{Section 9.2.2 of PQPAKE}}:

~~~
state, resp_msg = OQUAKE+.Respond(PRS, public_context, secret_context,
                                   init_msg, pk)
~~~

Here, `PRS` is the client's verifier, `pk` is the client's registered public
key, `secret_context` is `None`, and `public_context` is `encode_sid(sid, U, S)`,
where `sid` is the session identifier and `U` and `S` are the client and
server identifiers. This binds the session and party identities into the
key confirmation values that `OQUAKE+.Respond` computes internally.

The server's PAKEShare `pake_message` is `resp_msg`. The server's PAKE shared
secret is the `server_key` component of `state`. Note that the server does
not invoke `OQUAKE+.Verify` -- which would check `server_confirm` against a
client-sent value -- since the TLS Finished message from the client serves
this confirmation purpose instead. See {{oquakeplus-sec}} for more information
about the safety of this approach.

The server SHOULD NOT send application data before receiving a valid Finished
message from the client, which serves as confirmation that the client
derived the correct shared secret.

Upon receiving the server's PAKEShare `pake_message` (denoted `resp_msg`),
the client derives its shared secret by invoking `OQUAKE+.Finish`, as
specified in {{Section 9.2.3 of PQPAKE}}:

~~~
client_key, response = OQUAKE+.Finish(state, seed, resp_msg, public_context)
~~~

Here, `state` is the opaque state produced by the client's earlier call to
`OQUAKE+.Init`, `seed` is the seed from `GenVerifierMaterial`, and
`public_context` is `encode_sid(sid, U, S)` as above. The client's PAKE
shared secret is `client_key`; the `response` output value (the server's
confirmation value) is not sent to the server, since the `pake` extension
carries no third PAKEShare message for Internal PAKEs.

If `OQUAKE+.Finish` raises `AuthenticationError` -- which covers the key
confirmation value included in `resp_msg` not matching, `KEM.Decaps` failing,
or the client confirmation value not matching -- the client MUST abort the
handshake with a "decrypt_error" alert.

The client and server both combine their PAKE shared secret (`client_key` and
`server_key`, respectively) with the `(EC)DHE` shared secret as input to the
TLS 1.3 key schedule, where the (EC)DHE shared secret is as
specified in {{Section 7.1 of !TLS13=RFC8446}} or as the
`concatenated_shared_secret` as specified in {{Section 3.3 of !I-D.ietf-tls-hybrid-design}}.
Specifically, `client_key || (EC)DHE` is used as the `(EC)DHE` input to the key
schedule in {{Section 7.1 of !TLS13=RFC8446}}, as shown above in {{spake2plus-run}}.

The `secret_context` input to `OQUAKE+.Respond` and `OQUAKE+.Finish` is set
to `None` for standalone use of OQUAKE+ as an Internal PAKE; it is not `None`
when OQUAKE+ is composed with CPace, as in {{external-pakes}}.

# External PAKE Integration {#external-pakes}

## Overview {#external-overview}

External PAKEs provide an alternative approach for applications requiring:

* Multi-round PAKE protocols: Protocols requiring more than two messages to complete authentication
* Complex hybrid constructions: Sequential combinations of multiple PAKE protocols
* Application-controlled channels: Direct control over communication channels and timing
* Separation of concerns: Clear boundary between PAKE execution and TLS connection establishment

External PAKEs execute their complete protocol exchange outside of TLS, then integrate
with TLS through External PSK Import {{?RFC9258}}. This approach enables protocols
that cannot be constrained to the two-message limit of Internal PAKEs.

## General Framework {#external-framework}

External PAKE protocols must satisfy the following requirements:

* High-entropy output: Must derive a cryptographically strong shared secret
* PSK Import compatibility: Output must be suitable for External PSK Import per {{?RFC9258}}
* Secure session binding: Must provide mechanism to correlate out-of-band execution with TLS connection
* Forward secrecy: Must provide forward secrecy properties appropriate to the application

The integration pattern for External PAKEs follows these phases:

1. Out-of-band PAKE execution: Complete PAKE protocol exchange using application-controlled channels
2. PSK derivation: Use External PSK Import to derive TLS PSK from PAKE output
3. TLS PSK connection: Establish TLS connection using standard PSK mechanisms
4. Session correlation: Verify proper binding between PAKE execution and TLS connection

## CPaceOQUAKE+ Integration {#cpaceoquakeplus}

This section describes how CPaceOQUAKE+, the hybrid aPAKE from {{PQPAKE}},
can be realized using out-of-band PAKE execution followed by TLS integration
via External PSK Import {{?RFC9258}}. CPaceOQUAKE+ provides best-of-both-worlds
security: it remains secure if either the classical assumptions underlying CPace
or the post-quantum assumptions underlying OQUAKE+ hold.

### Overview {#cpaceoquakeplus-overview}

CPaceOQUAKE+ cannot be realized within a single TLS handshake because it requires
more than two PAKE messages. This specification describes an out-of-band approach:

1. CPace execution: Client and server execute CPace out-of-band to derive
   a shared secret (ISK).
2. OQUAKE+ execution: Client and server execute OQUAKE+ out-of-band using
   the CPace ISK as context to derive a hybrid secret.
3. TLS integration: Both parties import the hybrid secret as a PSK using
   {{?RFC9258}} External PSK Import and establish a standard TLS PSK connection.

The sequential composition provides hybrid security per the analysis in {{PQPAKE}}.
The out-of-band approach eliminates complex TLS session binding and allows
applications to control channel configuration.

### Protocol Setup {#cpaceoquakeplus-setup}

The TLS client and server roles map to the 'initiator' and 'responder' roles in
both the CPace and OQUAKE+ specifications, respectively. Clients are configured
with a password, client and server identities, and OQUAKE+ verifier material per
{{Section 9.1.1 of PQPAKE}}. Servers are configured with corresponding password
information and OQUAKE+ public key material.

Both parties must support CPace and OQUAKE+ protocols for out-of-band execution.
Applications configure out-of-band communication channels and TLS endpoints
separately. Servers must implement state management to correlate out-of-band
PAKE execution with subsequent TLS PSK connections.

The sequential composition follows the CPaceOQUAKE+ construction from {{PQPAKE}},
where CPace output serves as context input for OQUAKE+ to achieve hybrid security.

### Protocol Execution {#cpaceoquakeplus-execution}

The protocol execution follows three phases: CPace execution, OQUAKE+ execution
with CPace context, and TLS PSK integration.

~~~
Client                                Server
  |                                    |
  |-- CPace.Init --------------------->|
  |<-- CPace.Respond ------------------|
  | (both derive cpace_isk)            |
  |                                    |
  |-- OQUAKE+.Init ------------------->|
  |<-- OQUAKE+.Respond ----------------|
  | (both derive hybrid_secret)        |
  |                                    |
  | (both: external_psk = Import(hybrid_secret, "TLS 1.3 CPaceOQUAKE+ PSK", context))
  |                                    |
  |-- TLS ClientHello ---------------->|
  |    (with PSK extension)            |
  |<-- TLS ServerHello ----------------|
  |    (PSK selected)                  |
  |-- [TLS handshake completion] ----->|
  |<-- [TLS handshake completion] -----|
~~~

The detailed algorithm steps are:

First, CPace executes. This consists of the following:

~~~
- client_cpace_msg = CPace.Init(password, identities)
- server_cpace_msg = CPace.Respond(client_cpace_msg, password, identities)
- cpace_isk = CPace.Finish(server_cpace_msg)  // Both parties derive ISK
~~~

Second, OQUAKE+ executes with the CPace context as input.
This consists of the following:

~~~
- client_oquake_msg = OQUAKE+.Init(verifier, context=cpace_isk, identities)
- server_oquake_msg = OQUAKE+.Respond(client_oquake_msg, verifier, pk, context=cpace_isk)
- hybrid_secret = OQUAKE+.Finish(server_oquake_msg)  // Both parties derive final secret
~~~

The CPace ISK serves as context input for OQUAKE+ per the sequential combiner
construction. Both protocols execute completely outside TLS on application-configured
channels, with no intermediate TLS connections required.

When finished with the PAKE(s), both parties derive a TLS PSK
from the hybrid secret using {{?RFC9258}} External PSK Import.
This consists of the following:

~~~
- external_psk = Import(hybrid_secret, "TLS 1.3 CPaceOQUAKE+ PSK", context) // From RFC9258
- psk_identity = application_defined_identifier
- Standard TLS 1.3 PSK handshake using (external_psk, psk_identity)
~~~

The External PSK Import uses the following parameters:

- shared_secret: `hybrid_secret` from OQUAKE+.Finish output
- label: `"TLS 1.3 CPaceOQUAKE+ PSK"`
- context: Application-provided context or empty string
- hash: Hash function matching the TLS cipher suite

The TLS integration uses standard TLS 1.3 PSK mechanisms per {{Section 4.2.11 of !TLS13=RFC8446}}.
The PSK identity can be application-defined, with session correlation handled at the
application layer.

### Implementation Considerations {#cpaceoquakeplus-implementation}

Channel Security: Out-of-band channels must provide adequate confidentiality
and integrity for PAKE message exchange. Applications are responsible for
establishing secure communication channels for CPace and OQUAKE+ execution.

State Management: Applications must correlate out-of-band PAKE execution with
subsequent TLS connections. This includes managing PSK identities and ensuring
proper cleanup of server state.

Resource Management: Servers should limit concurrent out-of-band PAKE executions
to prevent resource exhaustion attacks. Consider the cumulative computational cost
of CPace and OQUAKE+ when setting limits.

Dictionary Attack Mitigation: Building on the general guidance in {{security}},
servers implementing out-of-band CPaceOQUAKE+ SHOULD:
- Rate-limit CPace initiation attempts per client identity
- Implement exponential backoff for failed out-of-band authentication attempts
- Monitor for repeated failures across the entire out-of-band sequence
- Consider the cumulative cost of CPace + OQUAKE+ execution when setting rate limits

Failure Handling: CPace and OQUAKE+ failures should be treated as authentication
attempts per the dictionary attack guidance. TLS PSK failures typically indicate
implementation errors rather than authentication failures. Failed out-of-band
sequences should trigger appropriate cleanup to prevent server state leaks.

# Privacy Considerations {#privacy}

Client and server identities are sent in the clear in the PAKEClientHello extension.
While normally the TLS server identity is already in the clear -- carried in
the SNI extension -- TLS client identities are encrypted under the TLS handshake
secrets. Thus, the PAKEClientHello extension reveals more information to a passive
network attacker than normal, mutually-authenticated TLS handshakes.

The implications of leaking the client identity to a passive network attacker vary.
For instance, a successful TLS handshake after negotiating use of a PAKE indicates
that the chosen client identity is valid. This is relevant in settings where
client enumeration may be a concern.

Applications for which this leak is a problem can use the TLS Encrypted ClientHello
(ECH) extension to encrypt the PAKEClientHello extension in transit to the server
{{?ECH=I-D.ietf-tls-esni}}.

# Security Considerations {#security}

## Dictionary attack mitigation

Because PAKE security is based on knowledge of a low-entropy secret,
an attacker can perform a "dictionary attack" by repeatedly attempting to
guess the low-entropy secret.

Clients and servers SHOULD apply mitigations against dictionary attacks.
Reasonable mitigations include rate-limiting authentication attempts,
imposing a backoff time between attempts, limiting the
number of failed attempts, or limiting the total number
of attempts.

Clients SHOULD treat each time they receive an invalid PAKEServerHello
as a failed authentication attempt for the identity in the previously sent PAKEClientHello.
Servers SHOULD treat each time they send a PAKEServerHello extension as a failed
authentication attempt for the selected identity, until they receive a correct Finished
message from the client. Once the server receives a correct Finished message,
the authentication attempt MAY be treated as successful.

## Protection of client identities

Many of the security properties of this protocol will derive from
the PAKE protocol being used. Security considerations for PAKE
protocols are noted in {{internal-pake-protocols}}.

If a server doesn't recognize the identity supplied by the
client in the ClientHello `pake` extension, the server MAY abort the handshake with an
"illegal_parameter" alert. In this case, the server acts as an oracle
for identities, in which each handshake allows an attacker
to learn whether the server recognizes a given identity.

Alternatively, if the server wishes to hide the fact that a client
identity is unrecognized, the server MAY simulate the protocol as
if an identity was recognized, but the password was incorrect.
This is similar to the procedure outlined in {{?RFC5054}}.
The simulation mechanism is described in {{simulation}}.

## Ramifications of low entropy secret compromise

As with PSK based authentication, if only PAKE authentication is in use,
then an attacker that learns the low entropy secret could impersonate
either the client or the server. In situations where a notion of stable identity
is available, then certificate-based authentication MAY be used as well to
reduce this risk. For example, requiring the server to authenticate with
a certificate in addition to PAKE authentication means an attacker
that learns the password could only impersonate a client to a server, but could not impersonate a server to a client.
This is an important distinction in situations where
the client sends sensitive data to the server.

## Internal PAKE Security Considerations

The following security considerations apply to Internal PAKEs that execute within
the TLS handshake using the `pake` extension.

### SPAKE2+ Security Considerations {#spake2plus-sec}

{{spake2plus}} describes how to integrate SPAKE2+ into TLS using the `pake`
extension in this document. This integration deviates from the SPAKE2+
protocol in {{SPAKE2PLUS}} in one important way: the explicit key confirmation
checks required in {{SPAKE2PLUS}} are replaced with the TLS Finished messages.
This is because the TLS Finished messages compute a MAC over the TLS transcript,
which includes both the `shareP` and `shareV` values exchanged for SPAKE2+.

OPEN ISSUE: this requires formal analysis to confirm.

### CPace Security Considerations {#cpace-sec}

{{cpace}} describes how to integrate CPace into TLS using the `pake`
extension in this document. Key confirmation is provided via TLS 1.3 Finished messages,
satisfying the requirements in {{Section 9.4 of !CPACE=I-D.irtf-cfrg-cpace}}.

### OQUAKE Security Considerations {#oquake-sec}

{{oquake}} describes how to integrate OQUAKE into TLS using the `pake`
extension in this document. The OQUAKE response message includes an explicit
key confirmation value `h` from server to client. The client MUST verify this
value. Client-to-server key confirmation is provided via TLS 1.3 Finished
messages.

### OQUAKE+ Security Considerations {#oquakeplus-sec}

{{oquakeplus}} describes how to integrate OQUAKE+ into TLS using the `pake`
extension in this document. This integration deviates from the full OQUAKE+
protocol in {{PQPAKE}} in one important way: the client does not send the
final `server_confirm` message (msg3). Instead, client-to-server key
confirmation is provided via TLS 1.3 Finished messages. This is analogous
to how SPAKE2+ integration ({{spake2plus}}) omits `confirmP` in favor of
TLS Finished.

The TLS Finished messages compute a MAC over the TLS transcript, which includes
both the OQUAKE+.Init and OQUAKE+.Respond messages. A client that cannot
derive the correct `client_key` (because it does not know the password seed)
cannot compute a valid Finished message, providing the server with equivalent
assurance to the explicit `server_confirm` verification.

OPEN ISSUE: this requires formal analysis to confirm.

## External PAKE Security Considerations

The following security considerations apply to External PAKEs that execute out-of-band
prior to TLS connection establishment.

### CPaceOQUAKE+ Security Considerations {#cpaceoquakeplus-sec}

{{cpaceoquakeplus}} describes how to integrate CPaceOQUAKE+ using out-of-band
execution followed by External PSK Import. The security of this composition relies on the sequential
PAKE combiner analysis from {{PQPAKE}}: by providing the CPace-derived context
to OQUAKE+, the effective password used in OQUAKE+ depends on both the original
password and the CPace session key. This means an attacker must break both CPace
and OQUAKE+ to mount an offline dictionary attack.

The binding between connections is achieved through the TLS Exporter, which
derives the context from the TLS Master Secret. An attacker that did not
participate in the first CPace handshake cannot predict or influence the
exported context value.

# IANA Considerations

This document requests that IANA add a value to the TLS
ExtensionType Registry with the following contents:

| Value | Extension Name | TLS 1.3 | Reference |
|:------|:---------------|:-------:|:---------:|
| 0xTODO   | pake           | CH, SH  | (this document)  |

RFC EDITOR: Please replace "TODO" in the above table with the
value assigned by IANA, and replace "(this document)" with the
RFC number assigned to this document.

## PAKE Scheme registry

This document requests that IANA create a new registry called
"PAKE Schemes" for internal PAKEs (those negotiated with the
PAKE extension) with the following contents:

| Value   | PAKEScheme | Reference | Notes |
|:--------|:-----------|:---------:|:------|
| 0xTODO  | SPAKE2PLUS_V1 | (this document) | N/A |
| 0xTODO  | CPACE_X25519_SHA512 | (this document) | N/A |
| 0xTODO  | OQUAKE_V1 | (this document) | N/A |
| 0xTODO  | OQUAKE_PLUS_V1 | (this document) | N/A |

The SPAKE2PLUS_V1 PAKEScheme variant has the following parameters associated with it:

* G: P-256
* Hash: SHA256
* KDF: HKDF-SHA256
* MAC: HMAC-SHA256

Additionally, it uses the M and N values from {{Section 4 of SPAKE2PLUS}}, included
below, as compressed points on the P-256 curve, for completeness.

~~~
M =
02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f

N =
03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49
~~~

The CPACE_X25519_SHA512 PAKEScheme variant has the parameters for 'CPACE-X25519-SHA512'
as specified in {{Section 4 of !CPACE=I-D.irtf-cfrg-cpace}}.

The OQUAKE_V1 PAKEScheme variant has the following parameters associated with it:

* BUA-sKEM: ML-BUA-sKEM1024
* KDF: HKDF-SHA-256
* DST: as specified in {{PQPAKE}}

These parameters correspond to the RECOMMENDED configuration in {{PQPAKE}}.

The OQUAKE_PLUS_V1 PAKEScheme variant has the following parameters associated with it:

* BUA-sKEM: ML-BUA-sKEM1024
* KEM: X-Wing {{XWING}}
* KDF: HKDF-SHA-256
* KSF: Argon2id {{ARGON2}} (parameters as specified in {{PQPAKE}})
* DST: as specified in {{PQPAKE}}

These parameters correspond to the RECOMMENDED configuration in {{PQPAKE}}.

# Acknowledgments
{:numbered="false"}

The authors would like to thank the original authors of {{FIRST-DRAFT}}
for providing a firm basis for the extension mechanism specified in this
document.

# Change Log
{:numbered="false"}

Since draft-ietf-tls-pake-01

* Add internal and external PAKE distinction
* Add OQUAKE and OQUAKE+ from draft-vos-cfrg-pqpake.

Since draft-ietf-tls-pake-00

* Add CPace as a second PAKE instantiation
* Require PAKE protocols to complete in exactly two messages
  (ClientHello and ServerHello)
* Require PAKE protocols to support key confirmation via TLS 1.3
  Finished messages
* Clarify server behavior when both pake and pre_shared_key
  extensions are present: server MUST select authentication
  mechanism based on preference, not client identity recognition
* Add explicit requirement that server MUST send missing_extension
  alert if pake extension is present without key_share and
  supported_groups extensions
* Specify that SPAKE2+ Context string MUST be prefixed with "tls"
  to prevent cross-protocol attacks

Since draft-bmw-tls-pake13-02

* Updated boilerplate after WG adoption

Since draft-bmw-tls-pake13-01

* Require standard TLS Key exchange to be combined with pake
* Allow combining PAKEs and certificates
