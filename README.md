# ahl-cli

The open self-hosted **client** of the [AHL Protocol](https://ahl-protocol.org) stack: offline
Evidence Receipt verification, authenticated revocation closure, and point-in-time
reconstruction against a log served by `atl-server` + `ahl-mirror` + `ahl-witness`.

It holds no log, serves no interface, and is not a conformance target of its own. It exercises
the verifier side of L1–L3.

## Commands

| Command | Input | Output | Network |
|---|---|---|---|
| `verify` | `.ahl` receipt + policy | verdict with rendered boundary | **never** |
| `inspect` | `.ahl` receipt | structural dump, **no verdict** | never |
| `emit` | statement payload + signing key | signed candidate envelope | never |
| `closure` | corpus or log + trigger reference | affected set + authentication state | optional |
| `reconstruct` | corpus or log + checkpoint + valid time | projection + authentication state | optional |

`verify` is offline by construction: the receipt format defines verification as receipt +
locally pinned profile + local policy, so there is **no flag that makes `verify` reach the
network**, and an assurance field that could only be raised by fetching is simply not raised.
In particular `assurance.witnessed` is true iff a cosignature *carried by the receipt* verifies;
whether a witness answers right now is irrelevant and cannot change the verdict.

Retrieval is a flag on `closure` and `reconstruct` only, never a verb of its own: fetching bytes
nobody verifies is not a feature.

```sh
ahl-cli --policy policy.toml verify evidence.ahl
ahl-cli --policy policy.toml --json verify evidence.ahl
ahl-cli --policy policy.toml inspect evidence.ahl

ahl-cli --policy policy.toml closure --trigger-index 6 --checkpoint 8 \
        --tree-material trees.json
ahl-cli --policy policy.toml closure --unauthenticated --corpus ./statements \
        --trigger sha256:<statement-id>

ahl-cli --policy policy.toml reconstruct --dataset customers \
        --record hmac-sha256:<commitment> --valid-time 2026-08-16T12:00:00Z --checkpoint 32

ahl-cli emit statement.json --key-file producer.seed --out statement.ahlentry
```

## Exit codes

Four outcomes, because collapsing "disproved" into "could not establish" is the mistake that
makes a verifier useless in CI.

| Exit | Outcome | Meaning |
|---|---|---|
| `0` | `valid` | every required rule verified |
| `1` | `invalid` | a normative rule fired against the artifact: structure, signature, proof, cross-field rule, equivocation between authenticated checkpoints, unknown claim or statement type |
| `2` | `error` | the CLI could not begin: usage, unreadable or unparseable policy, output-path I/O, internal invariant |
| `3` | `unverifiable` | well-formed, nothing disproved, but required evidence could not be established |

`0`, `1` and `2` carry exactly their `atl-cli` meanings, so a consumer written against the
family canon still reads them correctly. `3` is a documented AHL extension and is **never**
rendered as INVALID in any surface — text, JSON, or exit status.

Where more than one thing goes wrong: a rule fired against the artifact (`1`) outranks missing
external evidence (`3`), which outranks a local-environment failure (`2`) — except that a local
failure occurring before any artifact has been read is always `2`.

`--unauthenticated` is the one stated exception. In topology mode nothing is evidence, so
nothing can be disproved: rule violations found while walking an operator-supplied corpus are
**findings, not verdicts**, reported in full and never suppressed, with the outcome fixed at
`3`. Only a failure to read or parse the file at all is `2`.

`inspect` exits `0` when a dump was produced and `1` when the bytes are present but are not a
canonical receipt object. `0` there means "the dump exists" and never "the receipt is valid" —
the output carries no verdict field for a consumer to misread.

## The trust policy

```toml
[policy]
genesis_entry_id = "sha256:be129d…"
genesis_key_ids  = ["sha256:34750f…"]
trusted_witness_key_ids = []          # optional

[policy.limits]                        # optional; receipt-format §3.1 budgets
max_depth = 4
max_embedded = 64
max_decoded_bytes = 8388608
max_work_units = 100000

[policy.adaptor_profiles.ahl-test-log-v1]
hash = "sha256:13edfd…"                 # the pinned profile digest
path = "adaptor/ahl-test-log-v1.md"     # relative paths resolve against this file
checkpoint_raw = false                  # what the profile document defines
consistency_proofs = false

[policy.dataset_keys.customers]
file = "customers.key"                  # or: hex = "0505…"

[endpoints]                             # addresses, never authorities
mirror  = "https://mirror.example"
witness = "https://witness.example"

[limits.network]                        # separate from the receipt limits above
max_response_bytes = 33554432
max_total_bytes = 268435456
max_subrange_requests = 256
max_entries = 1048576
wall_clock_seconds = 300

[limits.local]
max_file_bytes = 33554432
max_corpus_entries = 1048576
```

The policy file, dataset-key files and signing keys are opened under **secure-open** rules:
open first, then check the *handle* — regular file, owner-only mode, owner matches the effective
uid — with `O_NOFOLLOW` on the final component. A `stat` followed by an `open` checks one file
and reads another; a hostile filesystem swapping a policy for one anchored to an attacker corpus
is the attack this closes.

Endpoints live outside `[policy]` deliberately: reading a URL must never look like reading a
trust anchor.

## Keys

`emit` needs a private signing key; `verify` and `inspect` never open one, and no code path
allows a verification command to touch signing material.

- `--key-file <path>` or `--key-env <NAME>`. **Never a command-line argument** — `argv` is
  world-readable in `ps`, and there is no flag that would accept one.
- One encoding: a single line of hex encoding a 32-byte Ed25519 seed, trailing newline optional.
  No PKCS#8, no PEM, no key files with headers, in v0.1.
- Secret bytes are never logged, never in JSON output, never in an error message, and are
  zeroized after use.

## `emit` produces a candidate, not a statement

`emit` performs the **locally decidable** checks only — statement-type schema, required members,
canonicalization (JCS), and value grammars such as the restricted duration form — and its output
is a **signed candidate envelope, not a conforming anchored statement**. The rules it cannot
evaluate are log-position-dependent by nature and are named in its own output: an introduction
at a smaller entry index, the active manifest binding, whether the signing key is active at the
entry index the log will assign, and trigger authority.

It never adds a field the operator did not supply, never signs an unknown statement type, and
never defaults a missing required field.

## Network behaviour

- **HTTPS only.** `--insecure` does not exist. Plain `http://` is accepted only when the
  **resolved peer address** is loopback, checked on the address actually connected to rather
  than on the hostname text; the client resolves once and hands the connector exactly those
  addresses, which is what closes DNS rebinding.
- **Redirects are not followed at all.** A redirect is a fetch failure naming the location; a
  redirect that would leave the configured host or downgrade the scheme is stronger than that
  and is refused outright (`2`).
- **Budgets are counted after decompression.** `Content-Length` is a hint, never a bound. The
  HTTP client's own limit bounds the *wire* bytes, which is a different budget: a kilobyte of
  gzip expands to a megabyte of zeroes, so the decompressed stream is bounded on top of it.
- **Chunking is client-driven.** Deterministic adjacent subranges under one fixed, already
  selected checkpoint; each subrange proof verified *before* concatenation against the
  **locally selected** `root_hash`; the subranges must tile the request exactly. There is no
  cursor — a server-supplied continuation token is not evidence.
- A response whose declared checkpoint does not match the selected
  `{log_id, tree_size, root_hash}` is rejected, but matching is on those **identity fields**,
  not byte-identity: a quiet log may legitimately publish several signed checkpoints at one size
  with the same root.
- **Refusal evidence is a witness artifact, not an HTTP status.** A mirror's 404, 500 or
  invented `reason` field is an operational failure and is reported as one.

## The cache

`--cache-dir` enables a **two-layer** cache: an object store keyed by the digest of the stored
bytes, and an **untrusted request index** mapping a request key to a digest. A "content hashes
only" cache is unimplementable, because a range response has no digest known before it is
fetched.

The request key binds the **locally selected checkpoint identity** `{log_id, tree_size,
root_hash}`, not merely endpoint and range: after an equivocation two distinct roots exist at one
`tree_size`, so a key built from endpoint + range + size would serve material from the wrong
branch.

The index has zero evidentiary weight. Every object is re-verified from its bytes on read
exactly as if it had just arrived, and every proof is re-checked against the locally selected
root — so a poisoned index can change *what work happens*, never *what is accepted*. A request
for the *latest* checkpoint is never served from cache: a valid old checkpoint is a replay.

`tests/cache_and_determinism.rs` holds the invariant the design requires: cold, warm and three
kinds of adversarially poisoned cache produce identical verdicts and identical exit codes,
evaluated against a fixed recorded transcript.

## Determinism

Same inputs plus same policy plus same `--evaluation-time` produce **byte-identical stdout**:
stable JSON key order, and every printed set ordered lexicographically by a stated field
(affected sets by `(dataset, record)`, findings by `(code, detail)`, key ids as strings).

Freshness is the only clock-dependent evaluation. `--evaluation-time` overrides it, and output
always carries `evaluation_time_source`, so an overridden result can never be read as a current
one. Checkpoint selection is a separate flag (`--checkpoint`); one flag never does both jobs.

## Ambiguities in the frozen sources, recorded rather than resolved

The frozen sources are `ahl-spec-draft.md` (core v0.3-draft), `ahl-receipt-format.md` r3 and
`ahl-adaptor-atl-v1.md`. Where they are silent, ambiguous or internally inconsistent, this
implementation reports the gap rather than choosing a reading and proceeding quietly. Each of
the following is also visible at runtime, as a `findings[]` entry or a named reason.

1. **`log.log_id` versus `log.id`.** Core §7.2/§7.3 and adaptor §7.3 name the manifest
   log-object member `log_id`; `ahl-core` reads `log.id`, and every manifest in the conformance
   corpus carries `id`. Both spellings are accepted here, `log_id` first, and using the legacy
   one raises the finding `manifest-log-id-legacy-spelling`. `emit` enforces the specification
   spelling, because it is producing a new statement and has no frozen corpus to accommodate.
2. **`log` object completeness.** Core §7.3 makes every member REQUIRED, including
   `cadence_epoch`; the corpus manifests omit several. Rejecting them would reject the frozen
   corpus, so the gap is reported as `manifest-log-object-incomplete` and the outcome is
   unchanged. `emit` again enforces the specification in full.
3. **Authentication and enumeration are mutually dependent.** Authenticating a checkpoint `C`
   needs the log key from the manifest version governing `tree_size(C)`; that manifest is an
   entry in the log; trusting entries needs `C`'s root. The design note orders them 1 then 2,
   which cannot be executed as a sequence. They are established here as a **joint fixed point**
   — see `src/anchored.rs` — and nothing is trusted on the way round.
4. **A series' earliest published member has no predecessor.** Adaptor §6.6 requires the
   predecessor consistency relationship for series-usability, while §5.2.2 item 3 explicitly
   permits an operator to publish no earlier member. The two cannot both hold for the earliest
   member, and refusing outright would make the whole series permanently unusable. The
   relationship is verified where a predecessor exists and the gap is named
   (`series-predecessor-unpublished`) where one does not.
5. **"Where a successor exists" is not decidable.** No authenticated completeness proof over
   checkpoint-series history is defined, so a mirror can withhold a successor and make an older
   `C` look newest. Series usability is therefore claimed only as `run-observed`, with the
   finding `series-successor-not-observed`.
6. **"The latest witnessed checkpoint" is not observable.** Core §4 requires consistency to it;
   nothing lets a client establish that a served checkpoint is the latest. `reconstruct`
   verifies consistency to the newest witnessed checkpoint *this run obtained* and labels it
   `continued_history_bound: run-observed`.
7. **An anchored object whose signatures do not verify.** Core §2.1 makes it not an AHL
   statement, and adaptor §7.4.1 requires ignoring such an object rather than treating the log
   as compromised — on a permissionless log anyone who can reach the submission endpoint can
   place one. Such entries are excluded from traversal and reported
   (`entry-is-not-a-statement`), never allowed to shift an entry index, and never fatal to an
   unrelated closure.
8. **Payload uniqueness in the conformance corpus.** Core §2.1 forbids anchoring two envelopes
   with the same statement id and makes the smallest entry index govern. Corpus entries 28, 29
   and 31 are three envelopes over one payload; under that rule the invalid-signature entry 28
   would govern and the co-signed entry 31 would be void, yet
   `trigger-effective-co-signed-by-authority.ahl` is expected to verify over entry 31. Reported
   as `statement-id-not-unique`, not adjudicated.
9. **The witness refusal wire form.** Adaptor §11.2 names the carried proof member `proof`;
   `ahl-witness` serves it as `consistency_proof`. Both are read, `proof` first, and the alias
   raises `witness-refusal-proof-member-alias`. The corpus's own refusal vector still declares
   the removed reason `inconsistent` (§11.2.4 removed it rather than renaming it), so that
   vector is *unusable* under the current profile — which is the finding, not a defect in
   either artifact.
10. **Committed tree material has no retrieval interface.** Adaptor §9 makes the complete leaf
    material of every committed tree corpus material a deployment MUST publish, but defines no
    interface for serving it and `ahl-mirror` serves none. `closure` therefore takes
    `--tree-material` as an out-of-band, untrusted root-to-leaves map, validated against the
    anchored root and count before any edge is read from it. Missing material is *named*, never
    assumed.
11. **`3` versus `1` for a dataset key that is not held.** `ahl-core` reports both "carried
    bytes do not recompute" and "no dataset key held" through one error variant, distinguished
    only by a sentinel string. The mapping to `3` is pinned by a test so a change upstream fails
    loudly rather than silently turning a `3` into a `1`.
12. **Two rows for redirects.** §6 makes a redirect missing evidence (`3`) and a cross-host or
    downgrade redirect a refused configuration (`2`), while §7 says redirects are never followed
    at all. Reconciled by the cross-host/downgrade qualifier: an ordinary same-origin redirect
    is `3`, one that leaves the origin or downgrades the scheme is `2`.
13. **Determinism versus `evaluation_time`.** §8 requires byte-identical stdout for the same
    inputs and policy, while §6 fixes `evaluation_time` in the output, which is a clock read
    unless overridden. Determinism therefore holds for a fixed `--evaluation-time`; without one,
    every field but that one is identical.

## Two additions to the §6 field list

`--json` carries two members §6's fixed list does not name, both added visibly rather than
silently:

- `receipt_note` — the receipt's informative `note`, quoted and attributed. §6 requires it to be
  displayed as a quotation attributed to the receipt and never as a finding, which the text
  surface alone could not give a `--json` consumer.
- `reconstruction` — the evidenced assertion set, present only on `reconstruct`, on the same
  footing as `affected` and `topology_affected`. The command has to return something, and §6
  names no member for it.

`inspect` and `emit` have their own stable JSON documents rather than the verdict schema:
`inspect` must print no verdict, so it must not carry a `status` field at all.

## What is deliberately out of scope in v0.1

- **Reproducible reconstruction.** The optional manifest-declared property requiring retention
  and retrieval of referenced artifacts and canonical input/output bytes is **not evaluated**,
  and `reconstruct` says so in its own output rather than leaving a reader to assume it. Core §4
  fixes the rule a later version must follow: erasure of any required content *terminates* the
  property, and the result must report it as terminated.
- Serving, writing to a log, key generation, interactive modes, and bulk export.
- Adaptor profiles other than `ahl-test-log-v1` and `ahl-adaptor-atl-v1`. A profile this build
  does not implement is reported as a limitation *of that profile*, named, never a silent
  fallback to whichever checkpoint signing form or leaf construction happens to verify.

## Building and testing

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
RUSTDOCFLAGS=-D warnings cargo doc --no-deps --all-features
cargo llvm-cov --all-features --ignore-filename-regex 'src/bin/' --fail-under-lines 90
```

The recorded network transcripts under `tests/fixtures/` are generated from the committed
`ahl-core` conformance corpus, with no clock read and no randomness:

```sh
cargo run --bin gen_fixtures
```

Two consecutive runs must leave `tests/fixtures/` byte-identical. If they do not, that is a bug.

Every receipt, closure, statement, checkpoint, Merkle and witness vector in
`../ahl-core/test_data` is exercised **end-to-end through the built binary** in `tests/`, not
only through the library: a verifier whose rules are only ever exercised in-process has never
demonstrated that its exit codes carry them, and the exit code is what a pipeline reads.

## License

Apache-2.0.
