---
title: Implicit ECH Configuration for TLS 1.3
abbrev: Implicit ECH Config
category: std
updates: draft-ietf-tls-esni-23


docname: draft-sullivan-tls-implicit-ech-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: ""
workgroup: "Transport Layer Security"
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
{{!ECH-DRAFT=I-D.draft-ietf-tls-esni-23}} to support an implicit mode in
ECH signaled by a new `implicit_ech` extension in `ECHConfigContents`.
Clients that detect this extension override certain base ECH rules:

- They MAY choose any outer SNI instead of `public_name`.
- They MAY choose any value for the `config_id` without an
  application profile or being externally configured.
- They MAY use another value than ECHConfig.contents.public_name
  in the "server_name" extension (rather than they SHOULD use it)

Client-facing servers that include `implicit_ech` in the ECHConfig MUST accommodate
flexible `config_id` usage as defined in Section 10.4. of {{ECH-DRAFT}}.
This approach enables the removal of stable identifiers (fixed config ID and
known public_name) that on-path adversaries can use to fingerprint a
connection.

This improves upon the "Do Not Stick Out" design goal
from Section 10.10.4 of {{ECH-DRAFT}} by allowing clients to choose
unpredictable identifiers on the wire in the scenario where the set of
ECH configurations the client encounters is small and therefore
popular `public_name` or `config_id` values "stick out".

Note that this increases CPU usage in multi-key deployments because
client-facing servers must perform uniform trial decryption to handle arbitrary
`config_id` values.


--- middle

# Introduction

The Encrypted ClientHello (ECH) protocol {{ECH-DRAFT}} is designed to hide
sensitive TLS handshake parameters, including the real SNI, from passive
observers. In the base ECH model, the client sets its outer SNI to
the public_name and config_id from the ECHConfig. Both of these can
become stable fingerprints that on-path adversaries recognize.

In implicit mode, the client MAY:

1. Select any outer SNI (rather than the public_name).
2. Select any config_id instead of taking it from the ECH configuration
   (without an application profile or extenal configuration agreement).

Client-facing servers that publish or accept implicit ECH configurations
must adjust key selection (e.g., single-key usage,
uniform trial decryption), removing reliance on stable config IDs or
well-known `public_name` values. This design helps conceal ECH usage
from on-path adversaries, though deployments may see increased CPU usage.

This proposal also addresses a timing side-channel in GREASE vs. real ECH,
by requiring client-facing servers supporting implicit ECH always to perform trial
decryption as defined in Section 10.4. of {{ECH-DRAFT}} — ensuring consistent
behavior regardless of ECH key validity.

This extension requires no changes to TLS servers, but does require operators to change
the format of their ECHConfigs advertised in DNS and in their retry configs. This is to
ensure that clients can successfully authenticate any retry configs provided via TLS.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Implicit ECH Extensions

This draft specifies two ECHConfig extensions. The first defines configuration information
and is used to advertise that a server supports Implicit ECH. The second authenticates
retry configs and is used when a server provides fresh retry_configs in its
Encrypted Extensions message.

## Implicit ECH Configuration Extension

A new ECHConfig extension type is defined to indicate implicit mode. If this
extension is present in ECHConfigContents.extensions, clients and client-facing
servers follow the rules described here, overriding certain parts of the base ECH
specification.

The extension has the following format:

~~~~
    enum { implicit_ech_config (TBD), (65535) } ECHConfigExtensionType;

    struct {
      HashAlgorithm hash_algorithm_id; // Needs a new IANA registry
      SignatureScheme signature_algorithm_id; // Defined in RFC 8446 4.2.3
      opaque retry_signing_key_hash<1..255>;
    } RetryKey;

    struct {
      RetryKey retry_keys<1..255>;
    } ImplicitECHConfig;
~~~~

The presence of this extension in the
ECHConfig signals to the client that the client-facing server is configured
for implicit ECH and follows the requirements of this document.

The extension conveys a list of public key hashes which correspond to public keys which can
be used to authenticate ECH retry configs.

## Implicit ECH Authenticator Extension

A new ECHConfig extension type is defined to authenticate implicit mode retry configs.

~~~~
    enum { implicit_ech_auth (TBD), (65535) } ECHConfigExtensionType;

    struct {
      uint32 not_after_timestamp; // Linux Epoch timestamp
      SignatureScheme signature_algorithm_id; // Defined in RFC 8446 4.2.3
      HashAlgorithm hash_algorithm_id; // Needs a new IANA registry
      opaque public_key<1..2^16-1>; // Parsed via signature_algorithm_id
      opaque signature<1..2^16-1>; // Parsed via signature_algorithm_id
    } ImplicitECHAuthenticator;
~~~~

Clients use the signature conveyed in this extension to authenticate the provided retry configs in the EncryptedExtension message.

The signature is computed over the message:

~~~~
  "ECH_implicit_retry_config_authenticator" || ech_config_payload
~~~~

The `ech_config_payload` consists of the ECHConfig itself, including all fields except the Signature part of the ImplicitECHAuthenticator. The ImplicitECHAuthenticator should always appear as the last extension (similar to the PSK extension in TLS).

TODO: There's a choice between having the ImplicitECHAuthenticator be an ECHConfig extension, conveyed inside retry_configs or
its own TLS extension. The latter is a bit cleaner, but violates the request-response pattern of TLS extensions unless we also
bump to a new ECH version. This also complicates how the server tells the client that ECH should be disabled. Putting the authenticator
inside the config means that we also need to define a variant of the config with an empty body to indicate "ECH should be disabled."

## Overridden Rules in the Base ECH Specification

When the implicit_ech extension is found in ECHConfigContents.extensions, the
following rules in {{ECH-DRAFT}} are overridden:

- The requirements for choosing the config_id in the ClientHello (Section 6.1.1.
  of {{ECH-DRAFT}}). In implicit mode, the client MAY choose any value for
  the config_id.

- Outer SNI usage (Section 6.1 of {{ECH-DRAFT}} says the client SHOULD set the
  value of the "server_name" extension to ECHConfig.contents.public_name. In
  implicit mode, the client MAY choose any valid domain name for the outer SNI.

# Client Behavior

If the client sees the implicit_ech extension in an ECHConfig:

- It MAY select any valid DNS name for the "server_name" extension,
  ignoring public_name.

- It MAY produce a random or arbitrary config_id, rather than
  using ECHConfigContents.key_config.config_id

Other aspects of the base ECH spec remain unchanged. In particular, the client
still picks a cipher suite from key_config.cipher_suites, produces a valid HPKE
ephemeral key, and encrypts ClientHelloInner into the payload field.

If ECH is accepted, then the same procedure as-in {{I-D.ietf-tls-esni}} is followed.
However, is ECH is rejected and the Implict ECH was advertised, the client must follow
a different strategy detailed in the next section.

## Behavior when ECH fails

Firstly, the client looks at the server's EncryptedExtensions message and checks for the presence
of an ECH extension with retry_configs. If present, the client extracts any provided ECHConfigs
which have the ImplicitECHAuthenticator extension and ignores any without it.

If the extension is present, the client must hash the provided PublicKey using indicated hash algorithm and check that it appears in the HashedPublicKey list provided in the initialImplicitECH extension. If so,
it must then validate the provided signature against that public key.

If the signature verifies, the client treats the retry_configs as authentic and uses them to retry
as specified in {{I-D.ietf-tls-esni, Section 6.1.6}} without considering the server's TLS certificate.
If the hashed public key does not appear in the provided list, or the signature does not verify,
the client must behave as though the server's TLS certificate could not be validated.

Note that regardless of whether the ImplicitECHAuthenticator is successfully validated, the client will terminate the
connection and retry with a fresh one. The only difference is whether the client treats the provided retry_configs as authentic.

If there are no retry_configs with valid ImplicitECHAuthenticators presented in the EncryptedExtensions message, then the client
considers the presented TLS certificate. The client verifies the presented TLS certificate against the name it selected for
the Client Hello Outer SNI. If the certificate validates for the Client Hello Outer and the issuing CA was loaded via Enterprise
policy, then the client can safely conclude it is behind a middlebox trusted by its administrator and retry without ECH. Otherwise,
if the certificate is not valid for the intended name or if the issuing CA was not loaded via Enterprise policy, the client
behaves as though the response could not be validated.

TODO: Better way to describe 'Enterprise Policy'? It's intended to encompass all non-WebPKI roots.

As described in Section 6.1.1 of {{ECH-DRAFT}}, in the event of HRR, the config_id
MUST be left unchanged for the second ClientHelloOuter.

# Client-Facing Server Behavior

A client-facing server that supports Implicit ECH on an IP address shared
with non-ECH services or GREASE ECH clients MUST attempt to decrypt the
encrypted ClientHello for every incoming connection that presents an ECH
extension. This requirement applies even if the `config_id` is not
recognized, so GREASE and valid ECH connections appear indistinguishable
from a timing perspective.

If the decryption attempt succeeds, the server proceeds with the handshake using
the inner ClientHello and the appropriate certificate chain for the actual
(inner) SNI. If the decryption attempt fails, there are two possibilities:

1. The client was connecting to a domain that does not support ECH
2. The client used a different ECHConfig than those currently supported on
   the client-facing server.

If trial decryption fails and the server recognizes the outer SNI, has a
certificate that covers it, and supports non-ECH connections for this
domain, then the server proceeds with a standard TLS handshake based
on the indicated SNI. Otherwise, the server selects whichever certificate
it would use as a fallback and proceeds with it.

As laid out in draft-ietf-tls-esni Section 7.0, the server SHOULD send an ECH retry_config extension
to provide the client with a fresh config, or leave it absent to indicate that
the client should disable ECH.

Servers which support Implicit ECH MUST also provide the ImplicitECHAuthenticator
extension whenever they respond. This extension allows clients using Implicit ECH
to authenticate the presence (or absence) of the ECH retry_configs. The ImplicitECHAuthenticator
can be prepared in advance and the TLS server itself does not require any behavioural changes
to generate or transmit it as it is communicated as part of the ECHConfig.

Servers can use a client's indicated SignatureScheme support to guide which ECH Retry Configs to send.

If multiple ECH keys are in rotation, perform uniform trial decryption
to avoid timing signals that reveal actual vs. unknown config_id usage. The
server SHOULD attempt ECH decryption first to avoid revealing whether
the `config_id` was recognized.

In this model, trial decryption on every connection ensures that GREASE
and real ECH connections are handled uniformly, preventing timing
side-channels.

# Deployment Considerations

Implicit config_id usage may require additional CPU overhead from trial
decryption for GREASE ECH handshakes. A single-key environment simplifies
ignoring the config_id and yields more uniform performance.

Supporting implicit ECH configurations limits the number of different ECH
keys supported by a server on the same IP address since the outer SNI and
config_id can no longer be used to choose the appropriate ECH configuration.

Deployments can support key rotation using the following strategy:
 * Add a new hashed public key to their ImplicitECHConfig
 * Wait for the new ECHConfig to propagate (DNS TTL)
 * Begin signing their retry_configs with the new public key.
 * Remove the old public key hash from their ImplicitECHConfig.

Deployments can handle key compromise by removing the affected public key
from their ImplicitECHConfig.

notAfter times SHOULD be at least 24 hours in the future and no more than 48 hours in the future. This allows
the server to tolerate clients with up to 24 hours clock skew, whilst limiting the ability of the attacker to
replay retry_configs in the future.

# Security Considerations

## Timing Side-Channels from Unknown IDs

In standard ECH, the server might quickly reject unknown hashed IDs. Implicit ECH
requires the server to attempt uniform decryption for IDs, reducing
the ECH vs. ECH GREASE timing gap.

## Hiding the Known public_name

By not placing `public_name` in the actual outer SNI, on-path adversaries
cannot block a known name. The client uses `public_name` only to authenticate
ECH retry hints, so an active attacker cannot degrade ECH without a valid
certificate.

## CPU Overhead

Randomized config_id and outer SNI usage can lead to increased CPU usage
from trial decryption. This cost grows if more than one ECH keys are
in use on the same server. Operators should consider minimizing the number
of active keys to mitigate this cost.

## Authentication of Retry Configs

{{I-D.ietf-tls-esni}} specifies how retry_configs are authenticated based on the public_name specified
in the ECHConfig and the provided TLS certificate. This extension uses a different approach.
The ECHConfig instead specifies one or more public keys and a signature by one of these keys
serves to authenticate the retry_configs.

This approach provides equivalent security. An attacker who can control the initial ECHConfig can
control authentication of the retry_configs in both cases. Authentication of the retry_configs
is necessary to prevent an attacker from disabling ECH by responding to the client's TLS connection
with a faked response from the server.

The inclusion of a notAfter timestamp in the retry_configs is necessary to prevent cut and paste
attacks between handshakes. An attacker that sees a signed retry_config can use it to reply to
other connection attempts. Consequently, it is necessary to limit the lifetime of these responses to
ensure that future clients can't be given old ECHConfigs which are no longer supported by the server.

NOTE: An alternative would be to include the client_random in the signature rather than a notAfter date. This
would avoid all replays attacks, but require more invasive changes to TLS servers and prevents the caching of ECHConfigs.

The need to support Enterprise Policy roots with missing ECH retry_configs extensions is because middleboxes will typically respond
without any ECH config in their response and hence without an authenticator to validate it.

Note: Alternative would be to just disable use of ECH when an Enterprise CA is configured.

# IANA Considerations

This document requests that IANA add the following entries to the "ECHConfig
Extension" registry:

- Value: TBD (suggested code point for `implicit_ech_config`)
- Extension Name: implicit_ech_config
- Recommended: Yes
- Reference: This document
- Notes: If present, the ECHConfig is "implicit," enabling ephemeral config_id
  usage and flexible outer SNI, as well as authentication by the listed public key hashes.

- Value: TBD (suggested code point for `implicit_ech_auth`)
- Extension Name: implicit_ech_auth
- Recommended: Yes
- Reference: This document
- Notes: If present, the ECHConfig is authenticated by this extension.

--- back

# Acknowledgments
{:numbered="false"}

Marwan Fayed and Chris Patton provided ideas and contributions to this draft.
