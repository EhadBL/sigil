# 📐 The Sigil Architecture & Protocol Specification
**Version:** 1.0.0-draft  
**Status:** Canonical Technical Standard  
**Authors:** Sigil Security Architecture Working Group  

---

## 1. Scope & Objective

Sigil is a zero-trust, cryptographically authenticated software distribution system designed to eliminate supply-chain vulnerabilities, registry takeovers, dependency confusion, in-flight tampering, and zero-day installation script execution.

This document formally specifies:
1. The `.sigil` package bundle and archive format.
2. The cryptographic algorithms, Merkle tree construction, and signature envelope schema.
3. The Transparency Log protocol and Merkle inclusion proof verification.
4. The client-side sandboxing, extraction invariants, and fail-closed trust engine.
5. The declarative capability permission system.

---

## 2. Cryptographic Primitives & Invariants

| Component | Standard Primitive | Specification | Purpose |
| :--- | :--- | :--- | :--- |
| **Signature Scheme** | **Ed25519** | PureEd25519 (RFC 8032) | Non-repudiation and author authenticity |
| **Hash Function** | **BLAKE3** | 256-bit default output | High-throughput collision-resistant digest |
| **Merkle Tree** | **Binary Merkle Tree** | RFC 6962 Domain Separation | $O(\log N)$ Inclusion & Consistency Proofs |
| **Encoding** | **Lower-case Hexadecimal** | RFC 4648 | Uniform serialization of digests and keys |
| **Canonical JSON** | **Deterministic JCS** | RFC 8785 | Signature malleability defense |

---

## 3. Package Bundle Format (`.sigil`)

A `.sigil` file is an uncompressed POSIX TAR archive (`GNU` format) holding strictly two canonical components:

```
my-package-1.0.0.sigil (TAR container)
├── envelope.sigil.json    (Canonical Cryptographic Metadata & Signature)
└── content.tar.gz         (Bit-for-Bit Deterministic Gzip-compressed Payload)
```

### 3.1. Envelope Schema (`envelope.sigil.json`)

The envelope is encoded in UTF-8 JSON and conforms to the following schema:

```json
{
  "manifest": {
    "package": {
      "name": "@acme/core-utils",
      "version": "1.0.0",
      "description": "Cryptographically verified core library",
      "authors": ["Alice <alice@acme.com>"],
      "license": "MIT",
      "repository": "https://github.com/acme/core-utils"
    },
    "capabilities": {
      "allow_network": false,
      "allow_fs_read": true,
      "allow_fs_write": false,
      "allow_env": false,
      "allow_child_process": false,
      "filesystem": {
        "read": ["./locales", "./config"],
        "write": []
      }
    },
    "dependencies": {}
  },
  "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "tree_root_hash": "b2f5c1d3f8a49c90823b1234567890abcdef1234567890abcdef1234567890ab",
  "files": [
    {
      "path": "index.js",
      "blake3_hash": "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225",
      "size_bytes": 1024
    }
  ],
  "timestamp": 1727265600,
  "author_pubkey": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  "signature": "3b29c9ef..."
}
```

### 3.2. Deterministic Archive Generation Rules
1. **Entry Sorting:** All directory entries MUST be sorted strictly in ascending lexicographical order by their UTF-8 relative path strings (using `/` as separator).
2. **Metadata Normalization:**
   - File modes (`mode`): normalized to `0o644` for files.
   - User ID (`uid`) and Group ID (`gid`): fixed to `0`.
   - Modification Time (`mtime`): fixed to Unix timestamp `0` (1970-01-01T00:00:00Z).
   - User/Group Names: empty strings.
3. **Compression:** Standard `flate2` Gzip with maximum compression (`Compression::best()`).

---

## 4. Cryptographic Tree & Signing Architecture

### 4.1. Domain-Separated Binary Merkle Tree
To prevent second-preimage attacks across leaves and interior nodes, Sigil enforces RFC 6962 domain prefixes:

$$\text{Leaf Hash } H_{\text{leaf}}(D) = \text{BLAKE3}(0\text{x}00 \mathbin{\Vert} D)$$

$$\text{Interior Node Hash } H_{\text{node}}(L, R) = \text{BLAKE3}(0\text{x}01 \mathbin{\Vert} L \mathbin{\Vert} R)$$

- For file manifests, each leaf payload is $D_i = \text{path}_i \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{hash}_i$.
- For transparency logs, each leaf payload is $D_i = \text{index} \mathbin{\Vert} \text{name} \mathbin{\Vert} \text{version} \mathbin{\Vert} \text{content\_hash} \mathbin{\Vert} \text{pubkey} \mathbin{\Vert} \text{prev\_hash}$.

### 4.2. Author Signature Verification
1. Reconstruct the canonical byte payload:
   $$\text{Canonical Payload} = \text{JCS}(\{ \text{name}, \text{version}, \text{content\_hash}, \text{tree\_root\_hash}, \text{timestamp}, \text{author\_pubkey}, \text{capabilities}, \text{dependencies} \})$$
2. Decode 64-byte Ed25519 signature $\sigma$.
3. Execute `ed25519::verify(author_pubkey, Canonical Payload, \sigma)`.
4. Any bit modification in code, manifest, capabilities, or declared dependencies invalidates the cryptographic signature.

---

## 5. Sigil Transparency Registry Protocol

### 5.1. Registry Ingestion Rules
When receiving a `POST /api/v1/publish` request:
1. **Payload Limit:** Reject payloads exceeding `64 MB`.
2. **Signature Verification:** Independently verify the author's Ed25519 signature before storage.
3. **Namespace Ownership Locking:**
   - On the first release of package `pkg`, record `package_owners[pkg] = author_pubkey`.
   - On subsequent releases, verify `author_pubkey == package_owners[pkg]`. Reject with `403 Forbidden` if mismatched.
4. **Release Immutability:** If `pkg@version` already exists in the log, reject with `409 Conflict`.
5. **Transparency Append:** Compute and store new Merkle Signed Tree Head (STH).

### 5.2. Core Registry API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Service health, total logged packages, and root head |
| `GET` | `/api/v1/tree/head` | Current Tree Size, Root Hash, and Timestamp |
| `POST` | `/api/v1/publish` | Uploads and registers a signed `.sigil` package |
| `GET` | `/api/v1/packages/:name` | Retrieves package versions and owner public key |
| `GET` | `/api/v1/packages/:name/:version/proof` | Returns RFC 6962 Merkle Inclusion Proof |
| `GET` | `/api/v1/packages/:name/:version/download` | Downloads verified `.sigil` file |

### 5.3. Trust-On-First-Use (TOFU) & Namespace Threat Model
In the current MVP architecture, registry namespace reservation operates on a **Trust-On-First-Use (TOFU)** basis:
- The first entity to publish `@scope/pkg` or `pkg` locks the namespace to their Ed25519 public key.
- **Threat Vector:** Malicious actors or squatters may claim reputable package names or organization scopes prior to the legitimate maintainer registering.

#### Defense in Depth & Mitigation Roadmap
1. **Client-Side Key Pinning (`sigil.trust.json`):**
   Clients do not blindly trust the registry's namespace mapping. Under `--enforce-trust`, the client strictly cross-references the package name and scope against locally pinned public keys. An unauthorized public key claiming a trusted scope is blocked at installation time.
2. **Federated Identity & OIDC Attestation (Roadmap):**
   Integration with OIDC identity tokens (Sigstore/Fulcio model), where keys are bound to cryptographic short-lived certificates issued via GitHub Actions, GitLab CI, or Google Workspace workflows.
3. **Domain & DNS Identity Verification (Roadmap):**
   Scoped organizations (e.g. `@acme/*`) must verify ownership via cryptographic DNS TXT challenge records (`_sigil-challenge.acme.com`) before the registry permits publishing.

### 5.4. Fail-Closed Client Transparency Verification
During package installation via `sigil add`, the client executes a zero-trust audit against the transparency log:
1. Queries the Merkle inclusion proof for the exact package version.
2. Computes the canonical leaf hash $D_i$ from local package metadata and the previous log link.
3. Validates the inclusion path against the registry root hash.
4. **Fail-Closed Guarantee:** If the registry returns an HTTP error, 404, or an invalid Merkle proof, the client immediately aborts installation and purges inbound artifacts. Split-view and log omission attacks are caught prior to extraction.
5. In isolated offline or local testing environments, users can explicitly opt out using the `--skip-transparency-proof` flag.

---

## 6. Client-Side Sandboxing & Safe Extraction

### 6.1. Invariants on Package Extraction
Extraction strictly rejects archives containing any of the following:
1. **Path Traversal Components:** Any `Component::ParentDir` (`..`), `Component::Prefix` (`C:`), or `Component::RootDir` (`/`).
2. **Illegal Characters:** Colons (`:`) or null bytes (`\0`).
3. **Symlinks & Hardlinks:** Any entry where `entry_type.is_symlink()` or `entry_type.is_hard_link()`.
4. **Decompression Bombs:**
   - Single file size limit: `64 MB`.
   - Cumulative package size limit: `256 MB`.
   - Envelope size limit: `5 MB`.

### 6.2. Content Integrity Guarantee
For each file extracted to destination:
1. Compute $\text{BLAKE3}(\text{extracted\_content})$.
2. Assert $\text{BLAKE3} == \text{envelope.files}[path].\text{blake3\_hash}$.
3. Verify that all files listed in the envelope were extracted with 0 missing and 0 extraneous files.

---

## 7. Trust Model & Key Lifecycle

1. **Zero-Trust Fail-Closed Rule:** If `--enforce-trust` is enabled, the client aborts installation unless the author's public key explicitly matches an authorized scope in `sigil.trust.json`. An empty keyring fails closed.
2. **Key Revocation (CRL):** A compromised key recorded in `revoked_keys` is permanently blacklisted across all scopes.
3. **Scoping Syntax:**
   - Wildcard: `*` (trust for all packages)
   - Namespace Scope: `@org/*` (trust for all packages under `@org/`)
   - Exact Package: `lodash` (trust exclusively for `lodash`)

---

## 8. Capability Permission Model

Packages declare static permissions in `sigil.toml`:

```toml
[package]
name = "@corp/secure-service"
version = "0.1.0"

[capabilities]
allow_network = true
allow_fs_read = true
allow_fs_write = false
allow_env = true
allow_child_process = false

# Fine-grained Declarative Restrictions
[capabilities.network]
hosts = ["api.internal.corp", "telemetry.corp.com"]

[capabilities.filesystem]
read = ["./locales", "./config"]
write = []

[capabilities.environment]
read = ["NODE_ENV", "PORT", "REGION"]
```

### 8.1. Runtime Enforcement Target
Sigil produces verified capabilities intended to be ingested directly by modern secure runtimes (e.g., Deno permissions `--allow-net=...`, Node.js Policy files, or WebAssembly WASI capability sandboxes).
