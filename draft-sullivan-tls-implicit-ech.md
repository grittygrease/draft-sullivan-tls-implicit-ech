---
title: Implicit ECH Configuration for TLS 1.3
abbrev: Implicit ECH Config
category: std
updates: draft-ietf-tls-esni-23


docname: draft-sullivan-tls-implicit-ech-00
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: Security
workgroup: tls
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
       ins: N. Sullivan
       name: Nick Sullivan
       organization: Cryptography Consulting LLC
       email: nicholas.sullivan+ietf@gmail.com

normative:
  RFC2119:
  RFC8446:
  I-D.draft-ietf-tls-esni-23:

informative:


--- abstract

This document updates the TLS Encrypted ClientHello (ECH) specification
{{!ECH-DRAFT=I-D.draft-ietf-tls-esni-23}} to support an implicit mode in ECH signaled by a new
`implicit_ech` extension in `ECHConfigContents`. Clients that detect this
extension override certain base ECH rules:

- They choose any outer SNI instead of `public_name`.
- They generate `config_id` ephemerally rather than hashing the server’s
  HPKE key.
- They validate ECH retry hints by checking that the server certificate
  covers `public_name`, instead of matching the outer SNI.

Servers that include `implicit_ech` in the ECHConfig MUST accommodate
flexible `config_id` usage. This approach removes stable identifiers (a
hashed config ID and a known public_name) that can be blocked by censors or
fingerprinted by middleboxes. It also increases CPU usage in multi-key
deployments, because servers must perform uniform trial decryption to handle
ephemeral `config_id` values.


--- middle

# Introduction

The Encrypted ClientHello (ECH) protocol {{ECH-DRAFT}} is designed to hide
sensitive TLS handshake parameters, including the real SNI, from passive
observers. In the base ECH model, the client sets its outer SNI to
the public_name from the ECHConfig and derives config_id by hashing the
server’s HPKE public key. Both of these can become stable fingerprints that
censors or middleboxes recognize.

In implicit mode, the client can:

1. Select any outer SNI (rather than the public_name).
2. Randomize config_id instead of deriving it from the HPKE key.

Servers that publish or accept implicit ECH configurations must adjust key
selection (e.g., single-key usage, uniform trial decryption), removing reliance
on stable hashed config IDs or well-known public_name. This design helps
conceal ECH usage from on-path adversaries, though deployments may see
increased CPU usage.

This proposal also addresses a timing side-channel in GREASE vs. real ECH, 
by requiring servers supporting implicit ECH to always attempt decryption
— ensuring consistent behavior regardless of ECH key validity.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Implicit ECH Extension

## Extension Definition and Semantics

A new ECHConfig extension type is defined to indicate implicit mode. If this
extension is present in ECHConfigContents.extensions, clients and servers
follow the rules described here, overriding certain parts of the base ECH
specification.

The extension has the following format:

~~~~
    enum { implicit_ech(TBD), (65535) } ECHConfigExtensionType;

    struct { // No data; presence indicates "implicit" usage } ImplicitECHConfig;
~~~~

The extension_data is zero-length. The presence of this extension in the
ECHConfig signals that the config_id used by the client may be ephemeral,
outer SNI need not match public_name, and retry hint verification uses
public_name coverage rather than SNI matching.

## Overridden Rules in the Base ECH Specification

When the implicit_ech extension is found in ECHConfigContents.extensions, the
following rules in {{ECH-DRAFT}} are overridden:

• Deterministic config_id derivation (section 4.1 of {{ECH-DRAFT}}). Instead of
  hashing the HPKE public key, the client MAY generate config_id as random
  or arbitrary bytes.

• Outer SNI usage (sections where {{ECH-DRAFT}} says the client SHOULD set SNI
  to public_name). In implicit mode, the client MAY choose any valid domain
  name or random string for the outer SNI.

• Verification of retry hints (sections referencing SNI-based certificate
  checks). In implicit mode, the client MUST ensure that the server’s
  certificate covers public_name from the ECHConfig rather than matching
  the SNI on the wire.

# Client Behavior

If the client sees the implicit_ech extension in an ECHConfig:

• It MAY select any outer SNI, ignoring public_name as the actual SNI string.

• It MAY produce a random or arbitrary config_id, rather than deriving it from
  the HPKE key.

• If the server issues an ECH retry hint (for example, in EncryptedExtensions),
  the client MUST confirm that the server certificate covers the original
  public_name from the ECHConfig. If coverage is lacking, the client discards
  the hint.

Other aspects of the base ECH spec remain unchanged. In particular, the client
still picks a cipher suite from key_config.cipher_suites, produces a valid HPKE
ephemeral key, and encrypts ClientHelloInner into the payload field.

# Server Behavior

A server that supports Implicit ECH on an IP address shared with non-ECH
services or GREASE ECH clients MUST attempt to decrypt the encrypted ClientHello
for every incoming connection that presents an ECH extension. This requirement
applies even if the `config_id` is not recognized, so GREASE and valid ECH
connections appear indistinguishable from a timing perspective.

If the decryption attempt succeeds, the server proceeds with the handshake using
the inner ClientHello and the appropriate certificate chain for the actual
(inner) SNI. If the decryption attempt fails, there are two possibilities:

1. The client was connecting to a domain that does not support ECH
2. The client used a different ECHConfig from the currently supported one on
   the server. 

If the server recognizes the outer SNI, has a certificate that covers it,
and supports non-ECH connections for this domain, then the server proceeds
with a standard TLS handshake based on the indicated SNI. Otherwise, the
server  MAY send an ECH retry hint in the `ServerHello`, accompanied by:

1. A newly issued or updated ECHConfig, possibly including the implicit
   flag again.  
3. A server certificate that covers the server_name in the supported
   ECHConfig, ensuring the client can verify it.  

If multiple ECH keys are in rotation, perform uniform trial decryption
to avoid timing signals that reveal actual vs. unknown config_id usage. The 
server SHOULD attempt ECH decryption first to avoid revealing whether
the `config_id` was recognized. 

In this model, trial decryption on every connection ensures that GREASE
and real ECH connections are handled uniformly, preventing timing
side-channels.

If the client’s ClientHello does not contain an ECH extension, the server
proceeds with a standard TLS handshake based on the indicated SNI. This
fallback behavior should remain unchanged from existing TLS handling. The
presence or absence of ECH extension data in the ClientHello is the primary
trigger for the server’s ECH logic.

# Deployment Considerations

Operators who choose this implicit mode remove reliance on stable hashed IDs or
a known public name as the outer SNI, improving censorship resistance. However,
implicit config_id usage may require additional CPU overhead from trial
decryption for GREASE ECH handshakes. A single-key environment simplifies ignoring
config_id and yields more uniform performance.

Supporting implicit ECH configurations limits the number of different ECH
keys supported by a server on the same IP address since the outer SNI and
config_id can no longer be used to choose the appropriate ECH configuration.

# Security Considerations

## Timing Side-Channels from Unknown IDs

In normal ECH, the server might quickly reject unknown hashed IDs. Implicit ECH
requires the server to attempt uniform decryption for IDs, reducing
the ECH vs. ECH GREASE timing gap.

## Hiding the Known public_name

By not placing `public_name` in the actual outer SNI, censors or middleboxes
cannot block a known name. The client uses `public_name` only to authenticate
ECH retry hints, so an active attacker cannot degrade ECH without a valid cert.

## CPU Overhead

Ephemeral config_id usage can lead to increased CPU usage from trial decryption.
This cost grows if more than one ECH keys are in use on the same server. Operators
should consider minimizing the number of active keys to mitigate this cost.

# IANA Considerations

This document requests that IANA add the following entry to the "ECHConfig
Extension" registry:

- Value: TBD (suggested code point for `implicit_ech`)
- Extension Name: implicit_ech
- Recommended: Yes
- Reference: This document
- Notes: If present, the ECHConfig is "implicit," enabling ephemeral config_id
  usage and flexible outer SNI.

--- back

# Acknowledgments
{:numbered="false"}

Marwan Fayed provided ideas and contributions to this draft.
