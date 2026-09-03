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
| `3` | `unverifiable` | well-formed, nothing disproved, but required evidence could not be established: a capability the verifier lacks, a local configuration it has not been given, or a local budget it has set |

`0`, `1` and `2` carry exactly their `atl-cli` meanings, so a consumer written against the
family canon still reads them correctly. `3` is a documented AHL extension and is **never**
rendered as INVALID in any surface — text, JSON, or exit status.

**`status` is the receipt's result; `outcome` is this run's decision, and the exit code follows
`outcome`.** `status` is exactly the result model's reduction of `assertions[]`, so two
conformant verifiers reach the same value over the same bytes whatever either one's local policy
says, and nothing rewrites it. `outcome` is `status` after the locally configured conditions in
`policy_overlays[]` are applied — a move from `valid` to `unverifiable` and nothing else.
Almost always the two are equal; where they differ, the text surface says so on its own line
(`receipt result: valid; policy: unverifiable (witness-freshness)`) so no reader mistakes a
condition of this run for the receipt's own result, and the boundary — the one thing rendered in
words that assert the property — is dropped along with the `valid`.

For `verify`, the first three are the three values of the AHL result model: a completed run
reaches exactly one of `verified`, `invalid` and `unverifiable`, and which one a rejection
produces is decided by `ahl-core` from the rule that fired, never re-derived here — a
verifier-local condition reported as `invalid` would let two verifiers make contradictory
statements about one artifact. A run that does not complete reaches no result at all and is
reported as the local failure it is, which is exit `2`.

The result is scalar — one receipt, one value — but it is not the whole report. `verify` also
reports one entry per required assertion of the receipt, in `assertions[]`, because the result
alone does not say which assertion produced it and a reader cannot act on `unverifiable`
without knowing what was missing. A receipt whose content binding cannot be computed reports
`unverifiable` as its result and `verified` on the assertions that did hold. A boundary is
rendered where the final status is `valid` and nowhere else — including where a CLI-level
assertion, and not the core, moved the status — and no result is ever expressed by rewriting the
receipt's own assurance fields: the assurance block is reproduced as carried on every outcome,
so a content binding the verifier could not compute is never re-rendered as
`content_binding: "none"`.

Where more than one thing goes wrong: a rule fired against the artifact (`1`) outranks missing
external evidence (`3`), which outranks a local-environment failure (`2`) — except that a local
failure occurring before any artifact has been read is always `2`.

`--unauthenticated` is the one stated exception. In topology mode nothing is evidence, so
nothing can be disproved: rule violations found while walking an operator-supplied corpus are
**findings, not verdicts**, reported in full and never suppressed, with the outcome fixed at
`3`. Only a failure to read or parse the file at all is `2`.

"Never suppressed" is a rule about the whole walk, not about one entry. A defect found while
collecting the corpus's governance chain — an unreadable payload, a missing statement type, a
manifest whose `predecessor` does not link to the version active immediately before it, a `key`
transition whose `key_id` does not recompute from its `pubkey` — **excludes that element and
reports it** (`governance-element-excluded`), keeps its position in the sequence, and the walk
continues. Ending the collection there would silence every check that runs after it, and the
list of violations is the one thing this mode exists to produce: a shorter list is not a safer
answer, it is a wrong one. Only two conditions leave nothing to walk *against* rather than
something to report — entries that do not ascend by entry index, and a corpus carrying no
manifest at all — and both say in as many words that signatures were not checked and why
(`corpus-governance-unresolvable`). Declaring every signature unverified instead would not be
noise but a false statement: with no key snapshot and no determinate key-state order, whether
a signature verifies is not a question the walk answered.

**Reaching either limit never discards what the walk already found.** A corpus whose only
manifest was excluded for breaking the predecessor rule ends with no manifest — and reports
*that*, alongside the general answer that no chain remained. Replacing the specific finding
with the general one would be the same suppression, moved to the last line: the walk knows why
the chain emptied, and the operator is the one who needs to be told.

`inspect` exits `0` when a dump was produced and `1` when the bytes are present but are not a
canonical receipt object. `0` there means "the dump exists" and never "the receipt is valid" —
the output carries no verdict field for a consumer to misread.

## The trust policy

```toml
[policy]
genesis_entry_id = "sha256:be129d…"
genesis_key_ids  = ["sha256:34750f…"]

[policy.trusted_witness_keys."sha256:c5b940…"]   # optional; whole entries, never bare ids
pubkey     = "base64:ypOsFw…"
witness_id = "witness-1"

[policy.limits]                        # optional; the two verifier-local budgets
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

A trusted witness key is configured as a whole entry — `pubkey` and `witness_id` beside the key
id — because the witness identity is inside the cosignature preimage: a key trusted to cosign
for one witness is not thereby trusted to cosign as another.

`[policy.limits]` carries the two verifier-local budgets and nothing else. The embedded nesting
depth (4) and embedded-receipt count (64) are fixed properties of the artifact, decided
identically by every verifier, so there is no key for them: a verifier able to lower either
would refuse a receipt another verifier accepts. Unknown keys are refused rather than ignored,
so a policy still carrying `max_depth` or `max_embedded` is reported as an unusable policy
(exit `2`) rather than silently read with the member dropped.

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

The index has **zero evidentiary weight**, and the cache's own digest check is not what
enforces that. Recomputing the digest of stored bytes is an integrity check on storage; an
attacker with write access to the cache directory can always store arbitrary bytes under their
own matching digest. What enforces the invariant is that the caller re-runs the same proof
checks a fresh response would get, against the **locally selected** root, and — on failure —
evicts and refetches exactly once (`net::fetch_revalidating`). A poisoned cache can therefore
change *what work happens*, never *what is accepted*. A request for the *latest* checkpoint is
never served from cache: a valid old checkpoint is a replay.

**Storing is a separate verb from fetching**, and that is what makes the retry honest. A fetch
never writes; a response reaches the store only after the caller's own proof checks have
accepted it. Writing a live answer the moment it arrived would file bytes nobody had verified
under the request key, and the eviction that follows a refusal would then report that the
refused answer had come from the cache — earning a repeat request against a live endpoint that
had simply answered badly, on the strength of a cache entry the same run had just manufactured.
With nothing stored until it verifies, an eviction can only ever have removed a genuinely
cached answer.

Every cache write goes through the same handle-relative, no-replace primitives as `emit`'s
output: an `O_EXCL` temporary under an unpredictable name inside an `O_NOFOLLOW` directory
handle. A cache entry has no evidentiary weight, but that was never a licence to let a symlink
planted in the cache directory redirect a write outside it.

`tests/cache_and_determinism.rs` holds the invariant the design requires: cold, warm and **four**
kinds of adversarially poisoned cache — corrupted objects, a dangling index, a cross-wired
index, and objects that are semantically wrong while hashing to exactly the digest the index
names — produce identical verdicts and identical exit codes, evaluated against a fixed recorded
transcript. The last of those is the one a digest check cannot catch, and it fails if the
eviction coupling is removed.

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

1. **Governance must be authenticated before it can authorize anything, and the order is not
   optional.** Adaptor §7.4.1 lists four tests a `manifest` or `key` statement must pass before
   it contributes to a resolved key set, of which test 2 — the producer signature, under the
   key set in force at its own entry index — can only be applied by building the chain
   **incrementally**. `Governance::resolve` does that; `Governance::structural_only` explicitly
   does not, is named so, and is used only in topology mode where nothing is evidence. A
   statement that fails is *ignored and reported* — `governance-statement-not-authorized` when
   the chain is being resolved for real, `governance-element-excluded` when it is being
   described in topology mode — never fatal: §7.4.1 says such an entry "is not a fork of the
   corpus".
2. **The order between core §2.1's two rules is unstated.** An envelope whose signatures do not
   all verify is not an AHL statement; separately, "if duplicates occur, the one with the
   smallest entry index governs and later ones are void". §2.1 does not say which applies
   first. This crate excludes non-statements *first*, because the other order hands an attacker
   a deletion primitive: anchoring a genuine payload with a broken signature at a smaller index
   would void the real statement. Reported here; both rules are pinned by tests over fixtures
   this crate controls. The same silence covers a *duplicate* whose statement type is not one
   of core §2.3's seven: §6 fixes an unknown statement type at `1` "never skipped, never
   inert", and §2.1 voids the later duplicate, and neither says which applies. This crate tests
   the type first, so "never skipped" holds for a repeated statement too.
3. **Authentication and enumeration are mutually dependent.** Authenticating a checkpoint `C`
   needs the log key from the manifest version governing `tree_size(C)`; that manifest is an
   entry in the log; trusting entries needs `C`'s root. The design note orders them 1 then 2,
   which cannot be executed as a sequence. They are established here as a **joint fixed
   point** — see `src/anchored.rs` — and nothing is trusted on the way round.
4. **The sources exempt one member from the predecessor rule, and no client can tell which.**
   Adaptor §6.6 requires the predecessor consistency relationship for series-usability, while
   §5.2.2 item 3 permits a deployment to have published no earlier member than the one it
   started at — so that member has nothing to relate to. Design note §3 item 3 nevertheless
   states the client rule as predecessor **always**, against successor *where one exists*.

   The asymmetry survives here because the exemption is a fact about the **deployment**, and
   the only thing a client sees is what one mirror answered. "The mirror served nothing
   earlier" is not "the deployment published nothing earlier": a `/v1/checkpoints` response is
   a server label, §2 rule 3 makes server labels not evidence, and §10 records that the frozen
   sources define no authenticated completeness proof over *any* history a server publishes —
   the same missing primitive that stops "where a successor exists" from being decidable.

   So **the exemption is never claimed.** Where no authenticated predecessor relationship is
   established the outcome is `3` with the missing element named, exactly as for any other
   evidence the client was not handed. Reading a short series response as the carve-out would
   hand every mirror a switch that turns a missing relationship into a complete answer: withhold
   the predecessor and a run that should report missing evidence reports `valid` instead.

   **The carve-out is therefore not implemented, and the cost is stated rather than hidden.** A
   deployment that genuinely did first publish at a larger size gets `unverifiable` on its own
   earliest member — a correct deployment answered conservatively, because this crate cannot
   tell that case from a withheld predecessor and the reporting rule of §10 says to name the
   gap rather than decide it in the client's own favour. Completeness below that member was
   never provable anyway. Both cases are pinned by their own tests, so adopting the carve-out
   later has to change a test rather than quietly change a verdict.

5. **"Where a successor exists" is not decidable.** No authenticated completeness proof over
   checkpoint-series history is defined, so a mirror can withhold a successor and make an older
   `C` look newest. Series usability is claimed only as `run-observed`, with the finding
   `series-successor-not-observed`.
6. **"The latest witnessed checkpoint" is not observable.** Core §4 requires consistency to it;
   nothing lets a client establish that a served checkpoint is the latest. `reconstruct`
   verifies consistency to the newest witnessed checkpoint *this run obtained* and labels it
   `continued_history_bound: run-observed`.
7. **An anchored object whose signatures do not verify.** Core §2.1 makes it not a statement,
   and adaptor §7.4.1 requires ignoring such an object rather than treating the log as
   compromised — on a permissionless log anyone who can reach the submission endpoint can place
   one. Such entries are excluded from **every** authenticated decision — introduction,
   authority, trigger selection, closure traversal — and reported (`entry-is-not-a-statement`).
   They never shift an entry index: the position is occupied by a placeholder, because the
   entry index is AHL's only ordering primitive.
8. **A digest check is not verification.** Design note §5 requires a cached object failing
   re-verification to be evicted and refetched once. "Re-verification" cannot mean the cache's
   own digest check: an attacker with write access to the cache directory can store arbitrary
   bytes under their own matching digest, and every digest check will pass. Eviction is
   therefore driven by the **caller's** proof checks, through `net::fetch_revalidating`, and
   the invariant test poisons the cache in a digest-consistent way so it fails if that
   coupling is ever removed. The same sentence fixes when a response may be *written*: "a
   cached object" is one that verified once, so a fetch stores nothing and `Caching::store` is
   called only after the caller has accepted the bytes. A repeat request is then earned only by
   an answer that really came out of the cache.
9. **Committed tree material has no retrieval interface.** Adaptor §9 makes the complete leaf
   material of every committed tree corpus material a deployment MUST publish, but defines no
   interface for serving it and `ahl-mirror` serves none. `closure` therefore takes
   `--tree-material` as an out-of-band, untrusted root-to-leaves map, validated against the
   anchored root and count before any edge is read from it. Missing material is *named*, never
   assumed.
10. **`3` versus `1` for a dataset key that is not held.** `ahl-core` reports both "carried
    bytes do not recompute" and "no dataset key held" through one error variant, distinguished
    only by a sentinel string. The mapping to `3` is pinned by a test so a change upstream
    fails loudly rather than silently turning a `3` into a `1`.
11. **Two rows for redirects.** §6 makes a redirect missing evidence (`3`) and a cross-host or
    downgrade redirect a refused configuration (`2`), while §7 says redirects are never
    followed at all. Reconciled by the cross-host/downgrade qualifier: an ordinary same-origin
    redirect is `3`, one that leaves the origin or downgrades the scheme is `2`.
12. **Determinism versus `evaluation_time`.** §8 requires byte-identical stdout for the same
    inputs and policy, while §6 fixes `evaluation_time` in the output, which is a clock read
    unless overridden. Determinism therefore holds for a fixed `--evaluation-time`; without
    one, every field but that one is identical.
13. **An unevaluated claim is not a disproved one.** A verifier that cannot evaluate
    `anchoring.consistency_path` must not report the receipt as `invalid`. This crate verifies
    the carried path independently, so it can tell "the path does not verify" (`1`) from "this
    verifier did not evaluate it" (`3`), and reports upstream's own wording for the former so a
    consumer written against the family canon still reads it.

14. **Series order is fixed; what to do when it cannot apply is not.** Core §7.3 orders a
    series by `(tree_size, checkpoint_time)` and makes the **earliest** `checkpoint_time` govern
    where a selection lands on a size carrying several members — but that rule presupposes the
    other half of the same paragraph, that members sharing a `tree_size` carry the same
    `root_hash`. Where they do not, the sources fix the *consequence* of a confirmed divergence
    (§5.2.2: the series ends from the **lowest** size at which it occurs, and choosing a branch
    is a conformance violation) without saying how a verifier is to find out whether the
    divergence is confirmed at all. Confirmation needs both members **authenticated**, and
    authentication resolves the signing key through the manifest version governing each
    member's own `tree_size` in its own corpus (§6.5 step 4).

    A run therefore has to reach the other branch's entries, and the request shape §10.3
    defines names a range and a tree size, never a root — so this client, speaking that one
    interface to one mirror, has no request that separates two roots at one size. **That is a
    limit on this client's repertoire, not a property of the protocol:** §10.3 leaves transport
    unconstrained and admits a published static archive or an independent mirror, and §6.6
    takes entry material from any source, so another party may well hold the other branch. What
    this crate reports is what *this run* established.

    Since an unresolved divergence is a candidate floor, it is treated as one. Ordered by size,
    ascending:

    - a size where a second root **does** authenticate under the chain this corpus authorizes is
      a confirmed floor: grounded at or beyond it, outcome `1` with the floor named; strictly
      below it, the finding `divergence-below-floor` and the outcome unchanged;
    - a size where it does not, and where this run could not establish that it authenticates
      under a chain of its own, is an **unresolved** floor. At or below the size the result
      would be grounded on, outcome `3`, naming what could not be established — never an
      accusation, which design note §7 reserves for two members that both authenticate.
      Strictly above it the result sits below the floor under every reading, members below a
      divergence remain usable, and it is carried as the finding
      `mirror-served-differing-roots` so that one bogus object cannot derail an honest run.

    The boundary is the size a result is grounded on, not the size the checkpoint was selected
    at, and it is `≤` rather than `==`: a divergence at a *smaller* size ends the series there,
    so a result grounded above it is grounded beyond a floor.

15. **`valid_from_index` compares on two scales, and the boundary differs.** Design note §2
    rule 4 requires a checkpoint's signing key to be in the governing version's `log.keys`
    *and* active by `valid_from_index`, which core §7.3 calls an entry index — but a checkpoint
    is selected by `tree_size`, and the sources never spell out the conversion. This crate
    reads it the way the manifest-selection rule already reads it: a checkpoint of size `n`
    commits exactly `[0, n)`, so a log or witness key is active for it when
    `valid_from_index < n`, the same strict boundary §7.3 uses to pick the governing version.
    On the entry-index scale — a producer key against an envelope's own index — both sides are
    entry indexes and the comparison is `valid_from_index <= index`, because a key is valid
    *from* that index. Recorded because the two boundaries differ and the sources state
    neither.

16. **A member republished at one `tree_size` is a series neighbour.** A quiet log MUST keep
    publishing at unchanged size, and series order is `(tree_size, checkpoint_time)`, so the
    republication is a genuine later member and §6.6's "where a following member exists" is
    satisfied by it. No consistency proof is fetched for such a pair: RFC 9162 defines none
    between a size and itself, so the relationship is settled by the roots — equal roots are the
    append-only extension of length zero, and unequal roots are the divergence adjudicated by
    the floor rule. Inventing a `from == to` request the profile does not define would be worse
    than checking what the two objects already say.

17. **A private rule in `ahl-core` cannot be safely mirrored by copying.** The client resolves
    governance from a **live enumeration**, which `ahl-core` does not expose an entry point for
    — it resolves governance only inside `verify_receipt`, from the chain a receipt carries — so
    the same normative rules are re-derived here against the same text. Two of them had already
    drifted out of that copy and were caught in review: the `key_id` recomputation of adaptor
    §7.2 / §6.5 step 4, and the cross-version `cadence_epoch` invariant of core §7.3 / adaptor
    §7.3.2. Both are now enforced and pinned.

    The structural fix is not in this crate's gift: it wants either a typed validation and
    binding primitive both crates consume, or cross-crate vectors both are run against. Until
    one exists, the client carries the vectors — `governance`'s manifest-schema and key-binding
    tests, including one that ties this crate's key-id recomputation to the family derivation
    `ahl-core` and `atl-core` use, so a change to that derivation fails here rather than
    diverging quietly.

### Settled since the first round

Three items this file previously recorded have been resolved upstream and the accommodations
for them are gone:

* the manifest log-object member is now `log_id` in the corpus as well as in the
  specification, so the `log.id` alias has been **removed** — a silent alias is how two
  incompatible dialects survive, and the value is load-bearing for binding a checkpoint to the
  corpus's Data Tree, so its absence is a check that cannot be performed rather than a
  reportable irregularity;
* `cadence_epoch` is present in the corpus manifests; it is also **immutable across versions**
  (core §7.3, adaptor §7.3.2), compared by value rather than by spelling, and a later version
  that moves it is rejected. The manifest schema of core §7.3 is
  now **checked rather than reported** wherever governance is resolved for real: "Every member
  is REQUIRED", so a signed manifest that omits one — or that carries a key object which cannot
  be read — is rejected and does not govern, and a genesis that breaks the schema is fatal
  because no later version can repair the corpus trust anchor. The
  `manifest-log-object-incomplete` finding survives only in `--unauthenticated` topology mode,
  where nothing is evidence and every violation is a finding rather than a verdict — and the
  topology walk now asks for those findings, which it previously did not, so a manifest key
  object that cannot be read is reported there rather than only left out of the key set. Every
  `key_id` is **recomputed from its `pubkey`** and a mismatch rejected — core §2.3.6 for
  producer keys, adaptor §7.2 and §6.5 step 4 for log and witness keys. The rule is about a
  *pair*, not a place, so it applies wherever a binding enters the resolved key set: a
  manifest's producer, `log` and `witness` key objects, **and** the `key` object of a
  transition statement, which is the primitive an authorized-but-compromised producer would
  otherwise use to install a key under a name of its choosing. Every reader of the key set goes
  through the same recomputation, so neither construction route — authenticated or
  topology-mode — can hand out a pair that was merely asserted;
* corpus entries 28, 29 and 31 no longer share one payload, and the witness refusal vector now
  declares `equivocation` rather than the removed `inconsistent`, so both are exercised as
  positives.

## Five additions to the §6 field list

`--json` carries five members §6's fixed list does not name, each added visibly rather than
silently:

- `assertions` — one entry per required assertion of the verified receipt, as
  `{assertion, outcome, receipt_path, detail, rests_on}`, with the assertion names and the three outcome
  values `ahl-core` reports. The result model requires the findings to be reported alongside
  the scalar result, and `findings[]` is a different list: it carries this crate's own
  diagnostic codes, such as `witness-stale`. `null` for a command that verifies no receipt.

  The list is the core's required assertions and **nothing else**: the result model enumerates
  them exactly, and a verifier-local condition among them would be this crate asserting
  something about the receipt another conformant verifier would not.

  A rejection the CLI reaches before the core is entered reports its assertion too, as a
  one-element list: `structure` for bytes that are not JSON, are not the JCS serialization, or
  name no adaptor profile, and `adaptor-profile` for a profile local policy does not hold. An
  `error` (`2`) result carries `null` — it reached no result value at all and is not a report
  about the receipt.

  `reason_code` names the assertion that **caused** the result, not the first non-`verified`
  entry in the list. The two differ whenever a budget runs out: every assertion the run could
  not reach then inherits the gap and carries `rests_on: "resource-limits"`, while the fact the
  reader needs — which budget, and the value in force — is on the cause. `rests_on` is `null` on
  a cause and names an assertion on a derived entry, so a consumer can reproduce the choice from
  the list rather than parse it out of prose. Where the core reached a result of its own, its
  cause is the headline; a policy overlay leads only where the core reached `verified`.
- `policy_overlays` — locally configured conditions this run applied on top of the receipt's own
  required assertions, each `{overlay, outcome, detail}`. Empty where none applied; this build
  has one, `witness-freshness`, present only where `--require-fresh` is given and a carried
  cosignature is older than the cadence plus grace period the governing manifest declares.
  Freshness is a property of the run's evaluation time rather than of the receipt, so it is
  verifier-local by construction: an overlay's `outcome` is `unverifiable` and never `invalid`,
  and without the flag freshness is a `findings[]` entry (`witness-stale`) and not an overlay
  at all.

  An overlay is evaluated on every completed run and reported whatever the receipt's result was.
  It can only ever move a `valid` one: a demonstrated defect outranks a condition of this run,
  so an overlay listed beside an `invalid` receipt is informative and changes nothing.
- `outcome` — **this run's decision**, in the same vocabulary as `status`, after the conditions
  in `policy_overlays[]` are applied. See below.
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
