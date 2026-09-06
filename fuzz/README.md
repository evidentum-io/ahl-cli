# ahl-cli fuzz targets

Four libFuzzer targets, one per surface the client exposes to input it did not produce.

`policy` takes arbitrary bytes through the trust policy reader — UTF-8, TOML, then the ordered
validation of the genesis anchor, the witness key sections, the adaptor profile entries, the
dataset key decode, the endpoint checks and the limit sections. `receipt` takes them through
the whole `verify` path under the corpus policy: the version read, the JCS canonicality check,
adaptor profile resolution, the `ahl-core` run and this crate's own freshness, quorum and
policy-overlay rows, with both `--require-fresh` settings driven. `topology` takes them through
the local corpus reader and the `closure --unauthenticated` topology walk, which decides entry
indexes, duplicates and envelope structure over material nobody authenticated. `response`
answers **every** mirror and witness request with the same fuzzed body and drives the whole
establishment — series parse and ordering, enumeration and tiling, root recomputation,
governance resolution, checkpoint authentication — plus the two parsers that take a body
directly, the §10.4 range response check and the §11.2.5 witness refusal check.

`policy`, `receipt` and `topology` enter through the parent crate's default-off `fuzzing`
feature, which exposes the parse-and-validate half of three entry points the client otherwise
reaches only through a file it opens under the design note §4 handle checks. Writing a file per
input would make every run an I/O benchmark, and the handle checks are not what is under test.
`response` needs no seam: `Fetcher` is a public trait, so the harness is simply a server.

All four handle every `Result` and index nothing; a panic reported by one is a defect in the
client, never in the harness. The limits are tightened well below the shipped defaults
(64 KiB per response, 32 subrange requests, 4 096 entries, 256 KiB per local file) so no single
input runs long.

Run them on nightly (libFuzzer needs it), passing the committed seeds as a second corpus
directory:

```sh
cargo +nightly fuzz build
mkdir -p fuzz/corpus/policy fuzz/corpus/receipt fuzz/corpus/topology fuzz/corpus/response
cargo +nightly fuzz run policy   fuzz/corpus/policy   fuzz/seeds/policy   -- -max_total_time=60
cargo +nightly fuzz run receipt  fuzz/corpus/receipt  fuzz/seeds/receipt  -- -max_total_time=60
cargo +nightly fuzz run topology fuzz/corpus/topology fuzz/seeds/topology -- -max_total_time=60
cargo +nightly fuzz run response fuzz/corpus/response fuzz/seeds/response -- -max_total_time=60
```

The seeds are derived from committed material. `seeds/policy/` holds nine policy files written
from the corpus trust anchor in `ahl-core/test_data/receipts/index.json`, one per section an
operator may write. `seeds/receipt/` holds one verifying and one rejecting receipt per claim
type, across all nine claim types; pass the `receipts/` directory of the `ahl-core` corpus as a
further corpus directory to start from the whole published corpus of 88. `seeds/topology/` holds every published
statement vector plus the array form a topology run is pointed at. `seeds/response/` holds the
recorded bodies from `tests/fixtures/mirror-transcript*.json`, deduplicated by content — every
checkpoint series and consistency body, and the six smallest range bodies, since a range
response has the same shape at every width and libFuzzer mutates a 59 KB input far less
effectively than a 6 KB one.

The fixture policy and the fixed evaluation instant live in `src/lib.rs`, built once per
process. The one file read per input is the pinned adaptor profile document: the client
resolves a profile from local possession at the point of use, hashing the bytes that run read,
and that is the behaviour under test rather than something to stub out.

`corpus/` and `artifacts/` are working directories and are not committed.
