//! The pilot scenario: the conformance corpus's story, replayed into the live stack.
//!
//! Eleven anchored statements — a genesis manifest, a producer-key addition, ingestions, a
//! batch derivation, a manifest version rotating the witness set, a correction, a retraction
//! and a propagation — then one receipt per claim type through `ahl-cli issue`, then
//! `ahl-cli verify` on each. The corpus's `receipts/index.json` is the oracle for what each
//! claim type should come out as; this module asserts the same outcomes over material no
//! generator produced.

use std::path::{Path, PathBuf};
use std::process::Command;

use ahl_core::{closure, hash_hex, jcs, statement_id, tree_root};
use serde_json::{json, Value};

use crate::scenario::{
    self, record, Record, DS_CUSTOMERS, DS_SCORES, PIPELINE, PRODUCER, T0, WITNESS_2,
};
use crate::stack::{http, Stack};

/// The result of one `ahl-cli` process run.
pub struct Run {
    /// The process exit code.
    pub code: i32,
    /// Everything written to stdout.
    pub stdout: String,
    /// Everything written to stderr.
    pub stderr: String,
}

impl Run {
    /// Both streams, for a failure report.
    pub fn output(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }

    /// The `--json` document.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|error| panic!("stdout is not JSON ({error}):\n{}", self.output()))
    }
}

/// Run the built binary, exactly as a foreign consumer would.
pub fn ahl_cli(args: &[&str]) -> Run {
    let output =
        Command::new(env!("CARGO_BIN_EXE_ahl-cli")).args(args).output().expect("the binary runs");
    Run {
        code: output.status.code().expect("the process exited normally"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// The records this corpus carries.
pub struct Records {
    /// The record a correction later replaces.
    pub a: Record,
    /// A second ingested record, signed by the added producer key.
    pub b: Record,
    /// A third ingested record, retracted late.
    pub c: Record,
    /// The replacement the correction names.
    pub a2: Record,
    /// The derived score.
    pub s1: Record,
}

impl Records {
    fn build() -> Self {
        Self {
            a: record(DS_CUSTOMERS, &json!({ "customer_id": "C-1001", "tier": "gold" })),
            b: record(DS_CUSTOMERS, &json!({ "customer_id": "C-1002", "tier": "silver" })),
            c: record(DS_CUSTOMERS, &json!({ "customer_id": "C-1003", "tier": "bronze" })),
            a2: record(DS_CUSTOMERS, &json!({ "customer_id": "C-1001", "tier": "platinum" })),
            s1: record(DS_SCORES, &json!({ "score": 720, "model": "risk-v4.2" })),
        }
    }
}

/// The root of a committed AHL tree over `leaves`, hashed the plain way of adaptor §9.
fn root_of(leaves: &[Value]) -> String {
    hash_hex(&tree_root(&leaves.iter().map(jcs).collect::<Vec<_>>()))
}

/// The transform block every derivation declares.
fn transform() -> Value {
    let params = json!({ "threshold_bp": 5000, "window_days": 90 });
    json!({
        "code": { "digest": ahl_core::sha256_hex(b"pilot-code-scoring-v1"), "type": "git_commit" },
        "model": { "digest": ahl_core::sha256_hex(b"pilot-model-risk-v4.2"), "version": "risk-v4.2" },
        "params": { "digest": ahl_core::sha256_hex(&jcs(&params)) },
    })
}

/// Write a statement payload where `ahl-cli emit` can read it.
fn write_payload(dir: &Path, name: &str, payload: &Value) -> PathBuf {
    let path = dir.join(format!("{name}.payload.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(payload).expect("serializable"))
        .expect("write the payload");
    path
}

/// Sign one statement through the product's own `emit`, and return the envelope file.
fn emit(dir: &Path, name: &str, payload: &Value, key_file: &Path) -> PathBuf {
    let payload_path = write_payload(dir, name, payload);
    let out = dir.join(format!("{name}.ahlentry"));
    let run = ahl_cli(&[
        "emit",
        &payload_path.display().to_string(),
        "--key-file",
        &key_file.display().to_string(),
        "--out",
        &out.display().to_string(),
    ]);
    assert_eq!(run.code, 0, "emit `{name}` failed:\n{}", run.output());
    out
}

/// The envelope a file holds.
fn envelope_at(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("the envelope file")).expect("JSON")
}

/// One `issue` invocation, with the endpoints and the loopback opt-in already supplied.
pub struct Issue<'a> {
    policy: &'a Path,
    log: String,
    extra_witness: String,
    work: PathBuf,
    /// The `--json` report of every successful run, by receipt name.
    reports: std::cell::RefCell<Vec<(String, Value)>>,
}

impl<'a> Issue<'a> {
    fn new(policy: &'a Path, stack: &Stack, work: &Path) -> Self {
        Self {
            policy,
            log: stack.log.base.clone(),
            extra_witness: stack.witness(WITNESS_2).to_owned(),
            work: work.to_path_buf(),
            reports: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// Assemble one receipt and return its path, or the run that failed.
    fn run(&self, name: &str, envelope: &Path, claim: &str, extra: &[&str]) -> (PathBuf, Run) {
        let out = self.work.join(format!("{name}.ahl"));
        let mut args: Vec<String> = vec![
            "--policy".to_owned(),
            self.policy.display().to_string(),
            "--json".to_owned(),
            "issue".to_owned(),
            "--envelope".to_owned(),
            envelope.display().to_string(),
            "--claim".to_owned(),
            claim.to_owned(),
            "--log".to_owned(),
            self.log.clone(),
            "--witness-endpoint".to_owned(),
            self.extra_witness.clone(),
            "--allow-insecure-loopback".to_owned(),
            "--out".to_owned(),
            out.display().to_string(),
        ];
        args.extend(extra.iter().map(|argument| (*argument).to_owned()));
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let run = ahl_cli(&borrowed);
        (out, run)
    }

    /// Assemble one receipt, insisting that it was assembled.
    fn must(&self, name: &str, envelope: &Path, claim: &str, extra: &[&str]) -> PathBuf {
        let (out, run) = self.run(name, envelope, claim, extra);
        assert_eq!(run.code, 0, "issue `{name}` ({claim}) failed:\n{}", run.output());
        self.reports.borrow_mut().push((name.to_owned(), run.json()));
        out
    }
}

/// Verify one receipt and return the parsed report.
pub fn verify(policy: &Path, receipt: &Path, extra: &[&str]) -> (i32, Value) {
    let mut args: Vec<String> = vec![
        "--policy".to_owned(),
        policy.display().to_string(),
        "--json".to_owned(),
        "verify".to_owned(),
        receipt.display().to_string(),
    ];
    args.extend(extra.iter().map(|argument| (*argument).to_owned()));
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let run = ahl_cli(&borrowed);
    assert!(!run.stdout.trim().is_empty(), "verify produced no report:\n{}", run.output());
    (run.code, run.json())
}

/// Everything the replay produced, for the assertions to read.
pub struct Replay {
    /// Receipt path by a short name.
    pub receipts: Vec<(String, PathBuf)>,
    /// Reasons a case the corpus has could not be produced here.
    pub skipped: Vec<(String, String)>,
    /// The `issue` report of each run, by the name given to `issue`.
    pub reports: Vec<(String, Value)>,
}

impl Replay {
    /// The `issue` report of the run under this name.
    pub fn report(&self, name: &str) -> &Value {
        self.reports
            .iter()
            .find(|(id, _)| id == name)
            .map_or_else(|| panic!("no `issue` run named `{name}`"), |(_, report)| report)
    }

    /// The receipt with this name.
    pub fn get(&self, name: &str) -> &Path {
        self.receipts.iter().find(|(id, _)| id == name).map_or_else(
            || panic!("no receipt named `{name}` was issued"),
            |(_, path)| path.as_path(),
        )
    }
}

/// Replay the whole story and issue one receipt per claim type.
///
/// The statements are anchored in entry order because `issue` anchors what it is given; a claim
/// about an entry already in the log finds it there and does not submit it twice.
#[allow(clippy::too_many_lines)] // One linear scenario; splitting it would obscure the order.
pub fn replay(pilot: &crate::Pilot) -> Replay {
    let stack = &pilot.stack;
    let policy = pilot.policy.as_path();
    let work = pilot.work.as_path();
    let genesis_statement_id = pilot.genesis.statement_id.as_str();
    let genesis_entry_id = pilot.genesis.entry_id.as_str();
    let keys = &pilot.keys;
    let key_files = &pilot.key_files;
    let cadence_epoch = pilot.genesis.cadence_epoch.as_str();
    let profile_hash = pilot.profile_hash.as_str();
    let records = Records::build();
    let p1 = key_files.get(PRODUCER).expect("the producer seed");
    let p2 = key_files.get("producer-2").expect("the second producer seed");
    let issue = Issue::new(policy, stack, work);
    let mut receipts: Vec<(String, PathBuf)> = Vec::new();
    let skipped: Vec<(String, String)> = Vec::new();

    let ingestion = |record: &Record, batch: &str, manifest: &str| {
        scenario::payload(
            "ingestion",
            manifest,
            PRODUCER,
            json!({
                "dataset": record.dataset,
                "record": record.commitment,
                "origin": format!("batch:{batch}"),
            }),
        )
    };
    let bytes_file = |name: &str, record: &Record| {
        let path = work.join(format!("{name}.record"));
        std::fs::write(&path, &record.bytes).expect("write the record bytes");
        path
    };

    // --- entry 1: a `key` statement adding the second producer key --------------------
    let key_payload = scenario::payload(
        "key",
        genesis_statement_id,
        PRODUCER,
        json!({
            "action": "add",
            "key": {
                "key_id": keys.producer_2.key_id(),
                "pubkey": keys.producer_2.pubkey(),
                "valid_from": T0,
            },
        }),
    );
    let key_envelope = emit(work, "01-key-add", &key_payload, p1);
    receipts.push((
        "key-anchored".to_owned(),
        issue.must("01-key-add", &key_envelope, "statement-anchored", &[]),
    ));

    // --- entries 2 and 3: two ingestions, the second under the key just added ---------
    let a_envelope =
        emit(work, "02-ingest-a", &ingestion(&records.a, "pilot-01", genesis_statement_id), p1);
    let a_bytes = bytes_file("a", &records.a);
    receipts.push((
        "record-ingested".to_owned(),
        issue.must(
            "02-ingest-a",
            &a_envelope,
            "record-ingested",
            &[
                "--dataset",
                DS_CUSTOMERS,
                "--record",
                &records.a.commitment,
                "--record-bytes",
                &a_bytes.display().to_string(),
                "--canonicalization",
                scenario::CANONICALIZATION,
            ],
        ),
    ));

    let mut b_payload = ingestion(&records.b, "pilot-01", genesis_statement_id);
    if let Some(map) = b_payload.as_object_mut() {
        map.insert("producer".to_owned(), json!(PRODUCER));
    }
    let b_envelope = emit(work, "03-ingest-b", &b_payload, p2);
    let b_bytes = bytes_file("b", &records.b);
    receipts.push((
        "record-ingested-second-key".to_owned(),
        issue.must(
            "03-ingest-b",
            &b_envelope,
            "record-ingested",
            &[
                "--dataset",
                DS_CUSTOMERS,
                "--record",
                &records.b.commitment,
                "--record-bytes",
                &b_bytes.display().to_string(),
                "--canonicalization",
                scenario::CANONICALIZATION,
            ],
        ),
    ));

    // --- entry 4: a batch derivation, committing an output tree and an input-set tree --
    let a_statement = statement_id(&envelope_at(&a_envelope)).expect("a well-formed envelope");
    let b_statement = statement_id(&envelope_at(&b_envelope)).expect("a well-formed envelope");
    // I-D §2.7: leaves are sorted by `record`, ascending over the UTF-8 bytes of the
    // commitment string, and duplicates are prohibited.
    let mut input_leaves = vec![
        json!({ "dataset": DS_CUSTOMERS, "record": records.a.commitment, "role": "feature", "statement": a_statement }),
        json!({ "dataset": DS_CUSTOMERS, "record": records.b.commitment, "role": "reference", "statement": b_statement }),
    ];
    input_leaves.sort_by_key(|leaf| leaf["record"].as_str().unwrap_or_default().to_owned());
    let input_root = root_of(&input_leaves);
    let output_leaves = vec![json!({
        "dataset": DS_SCORES,
        "record": records.s1.commitment,
        "inputs": { "input_set_root": input_root, "input_set_count": input_leaves.len() },
    })];
    let outputs_root = root_of(&output_leaves);
    let derivation = scenario::payload(
        "derivation",
        genesis_statement_id,
        PRODUCER,
        json!({
            "pipeline": PIPELINE,
            "outputs_root": outputs_root,
            "outputs_count": output_leaves.len(),
            "leaf_format": "ahl-leaf-v2",
            "inputs": [
                { "dataset": DS_CUSTOMERS, "record": records.a.commitment, "role": "feature", "statement": a_statement },
                { "dataset": DS_CUSTOMERS, "record": records.b.commitment, "role": "reference", "statement": b_statement },
            ],
            "transform": transform(),
        }),
    );
    let derivation_envelope = emit(work, "04-derivation", &derivation, p1);

    // --- entry 5: manifest version 2, rotating the witness set ------------------------
    let v2 = scenario::manifest(keys, profile_hash, 5, cadence_epoch, Some(genesis_entry_id));
    let v2_envelope = emit(work, "05-manifest-v2", &v2, p1);
    let v2_statement = statement_id(&envelope_at(&v2_envelope)).expect("a well-formed envelope");

    // Every tree this corpus commits, in the shape a receipt carries them.
    let disposition_leaves = vec![
        json!({ "dataset": DS_SCORES, "record": records.s1.commitment, "disposition": "invalidated" }),
    ];
    let affected_root = root_of(&disposition_leaves);
    let trees = work.join("trees.json");
    let mut material = serde_json::Map::new();
    material.insert(outputs_root.clone(), json!({ "leaves": output_leaves }));
    material.insert(input_root.clone(), json!({ "leaves": input_leaves }));
    material.insert(affected_root.clone(), json!({ "leaves": disposition_leaves }));
    std::fs::write(&trees, serde_json::to_vec_pretty(&material).expect("serializable"))
        .expect("write the tree material");

    receipts.push((
        "record-derived".to_owned(),
        issue.must(
            "04-derivation",
            &derivation_envelope,
            "record-derived",
            &[
                "--dataset",
                DS_SCORES,
                "--record",
                &records.s1.commitment,
                "--tree-material",
                &trees.display().to_string(),
            ],
        ),
    ));
    receipts.push((
        "manifest-anchored".to_owned(),
        issue.must("05-manifest-v2", &v2_envelope, "statement-anchored", &[]),
    ));

    // --- entries 6 and 7: the retracted record and the correction's replacement -------
    let c_envelope =
        emit(work, "06-ingest-c", &ingestion(&records.c, "pilot-02", &v2_statement), p1);
    let c_bytes = bytes_file("c", &records.c);
    let intro_c = issue.must(
        "06-ingest-c",
        &c_envelope,
        "record-ingested",
        &[
            "--dataset",
            DS_CUSTOMERS,
            "--record",
            &records.c.commitment,
            "--record-bytes",
            &c_bytes.display().to_string(),
            "--canonicalization",
            scenario::CANONICALIZATION,
        ],
    );
    receipts.push(("record-ingested-after-rotation".to_owned(), intro_c.clone()));

    let replacement_envelope =
        emit(work, "07-ingest-a2", &ingestion(&records.a2, "pilot-02", &v2_statement), p1);
    let replacement_bytes = bytes_file("a2", &records.a2);
    let intro_a2 = issue.must(
        "07-ingest-a2",
        &replacement_envelope,
        "record-ingested",
        &[
            "--dataset",
            DS_CUSTOMERS,
            "--record",
            &records.a2.commitment,
            "--record-bytes",
            &replacement_bytes.display().to_string(),
            "--canonicalization",
            scenario::CANONICALIZATION,
        ],
    );

    // --- entry 8: the correction, which is the trigger the propagation acts on --------
    let correction = scenario::payload(
        "correction",
        &v2_statement,
        PRODUCER,
        json!({
            "dataset": DS_CUSTOMERS,
            "record": records.a.commitment,
            "replacement": records.a2.commitment,
            "reason_code": "error",
            "scope": { "effective_from": T0, "retroactive": true },
        }),
    );
    let correction_envelope = emit(work, "08-correction", &correction, p1);
    let intro_a = receipts
        .iter()
        .find(|(name, _)| name == "record-ingested")
        .map(|(_, path)| path.clone())
        .expect("the introduction of record A");
    receipts.push((
        "trigger-declared".to_owned(),
        issue.must(
            "08-correction",
            &correction_envelope,
            "trigger-declared",
            &[
                "--dataset",
                DS_CUSTOMERS,
                "--record",
                &records.a.commitment,
                "--introduction",
                &intro_a.display().to_string(),
                "--replacement-introduction",
                &intro_a2.display().to_string(),
            ],
        ),
    ));

    // --- entry 9: a second trigger, so the competing range is not trivially empty -----
    let retraction = scenario::payload(
        "retraction",
        &v2_statement,
        PRODUCER,
        json!({
            "dataset": DS_CUSTOMERS,
            "record": records.c.commitment,
            "reason_code": "consent_withdrawn",
            "scope": { "effective_from": T0, "retroactive": true },
        }),
    );
    let retraction_envelope = emit(work, "09-retraction", &retraction, p1);
    receipts.push((
        "retraction-anchored".to_owned(),
        issue.must("09-retraction", &retraction_envelope, "statement-anchored", &[]),
    ));

    // --- the correction again, now as an effective trigger under enumerated governance -
    let trigger_effective = issue.must(
        "10-trigger-effective",
        &correction_envelope,
        "trigger-effective",
        &[
            "--dataset",
            DS_CUSTOMERS,
            "--record",
            &records.a.commitment,
            "--introduction",
            &intro_a.display().to_string(),
            "--replacement-introduction",
            &intro_a2.display().to_string(),
        ],
    );
    receipts.push(("trigger-effective".to_owned(), trigger_effective.clone()));

    // --- entry 10: the propagation, complete at the checkpoint it declares ------------
    let declared_size = 10u64;
    let declared = signed_checkpoint(stack, declared_size);
    let corpus = corpus_envelopes(stack, declared_size);
    let tree_material: closure::TreeMaterial = [
        (outputs_root.clone(), leaves_of(&trees, &outputs_root)),
        (input_root.clone(), leaves_of(&trees, &input_root)),
    ]
    .into_iter()
    .collect();
    let trigger_index = 8;
    let computed = closure::affected_set(
        &corpus,
        &tree_material,
        trigger_index,
        usize::try_from(declared_size).expect("a small tree"),
    )
    .expect("the corpus and its tree material");
    assert_eq!(
        computed.affected.len(),
        leaves_of(&trees, &affected_root).len(),
        "the disposition tree does not anchor the closure this corpus recomputes"
    );

    let propagation = scenario::payload(
        "propagation",
        &v2_statement,
        PRODUCER,
        json!({
            "trigger": statement_id(&envelope_at(&correction_envelope)).expect("a trigger"),
            "corpus_checkpoint": {
                "log_id": declared["log_id"],
                "root_hash": declared["root_hash"],
                "tree_size": declared["tree_size"],
            },
            "affected_root": affected_root,
            "affected_count": 1,
            "complete_relative_to_manifest": true,
        }),
    );
    let propagation_envelope = emit(work, "11-propagation", &propagation, p1);
    receipts.push((
        "propagation-complete".to_owned(),
        issue.must(
            "11-propagation",
            &propagation_envelope,
            "propagation-complete",
            &[
                "--trigger",
                &trigger_effective.display().to_string(),
                "--tree-material",
                &trees.display().to_string(),
            ],
        ),
    ));
    receipts.push((
        "disposition-effective".to_owned(),
        issue.must(
            "12-disposition-effective",
            &propagation_envelope,
            "disposition-effective",
            &[
                "--dataset",
                DS_SCORES,
                "--record",
                &records.s1.commitment,
                "--trigger",
                &trigger_effective.display().to_string(),
                "--tree-material",
                &trees.display().to_string(),
            ],
        ),
    ));
    let trigger_declared = receipts
        .iter()
        .find(|(name, _)| name == "trigger-declared")
        .map(|(_, path)| path.clone())
        .expect("the declared trigger");
    receipts.push((
        "disposition-declared".to_owned(),
        issue.must(
            "13-disposition-declared",
            &propagation_envelope,
            "disposition-declared",
            &[
                "--dataset",
                DS_SCORES,
                "--record",
                &records.s1.commitment,
                "--trigger",
                &trigger_declared.display().to_string(),
                "--tree-material",
                &trees.display().to_string(),
            ],
        ),
    ));

    // --- the governance state at an index no governance statement follows -------------
    receipts.push((
        "governance-state".to_owned(),
        issue.must(
            "14-governance-state",
            &v2_envelope,
            "governance-state",
            &["--target-index", "9"],
        ),
    ));

    // --- entry 11: a trigger issued by a key the dataset authority does not name -----
    // Core spec §2.3.3: a trigger not signed by the record's authority anchors as a challenge
    // and never governs. `producer-2` is an active producer key from manifest version 2, so the
    // envelope itself verifies — which is the point: what fails is authority, not signing.
    let unauthorised = scenario::payload(
        "retraction",
        &v2_statement,
        "producer-2",
        json!({
            "dataset": DS_CUSTOMERS,
            "record": records.c.commitment,
            "reason_code": "consent_withdrawn",
            "scope": { "effective_from": T0, "retroactive": true },
        }),
    );
    let unauthorised_envelope = emit(work, "15-unauthorised-trigger", &unauthorised, p2);
    receipts.push((
        "trigger-effective-unauthorised".to_owned(),
        issue.must(
            "15-unauthorised-trigger",
            &unauthorised_envelope,
            "trigger-effective",
            &[
                "--dataset",
                DS_CUSTOMERS,
                "--record",
                &records.c.commitment,
                "--introduction",
                &intro_c.display().to_string(),
            ],
        ),
    ));

    // --- entry 12: an anchored entry whose producer signature does not verify --------
    // I-D §7.5.1 4d: a resolvable key whose signature does not verify is `invalid`. The corpus
    // makes this vector by rebuilding its tree around the corrupted envelope; a live log cannot
    // be asked to do that, because the entry id is the leaf. So the envelope is built
    // non-verifying BEFORE it is anchored — the signature is a real one by an active key over
    // different bytes — and the log anchors it, as a log with no submission controls will.
    let d = record(DS_CUSTOMERS, &json!({ "customer_id": "C-1004", "tier": "unsigned" }));
    let d_payload = ingestion(&d, "pilot-03", &v2_statement);
    let borrowed_signatures = envelope_at(&a_envelope)["signatures"].clone();
    let bad = json!({ "payload": d_payload, "signatures": borrowed_signatures });
    let bad_path = work.join("16-bad-signature.ahlentry");
    std::fs::write(&bad_path, jcs(&bad)).expect("write the envelope");
    receipts.push((
        "statement-anchored-bad-signature".to_owned(),
        issue.must("16-bad-signature", &bad_path, "statement-anchored", &[]),
    ));

    // --- the continued history, over an entry the log has long since grown past ------
    // The `key` statement at entry 1 was anchored under the checkpoint of tree size 2 and is
    // re-issued here, at the end, with the log seventeen entries long. `issue` places an
    // already-anchored entry under the EARLIEST series-usable checkpoint that commits it, so
    // the receipt is grounded where the statement actually was, and the growth since is carried
    // as `continued_history` — a later checkpoint, the mirror's consistency proof between the
    // two, and a cosignature over the later state.
    receipts.push((
        "statement-anchored-continued-history".to_owned(),
        issue.must("17-continued-history", &key_envelope, "statement-anchored", &[]),
    ));

    Replay { receipts, skipped, reports: issue.reports.take() }
}

/// The ATL Evidence Receipt the log publishes for one of its own entry identifiers.
pub fn atl_receipt(stack: &Stack, atl_entry_id: &str) -> Value {
    let path = format!("/v1/anchor/{atl_entry_id}");
    let (status, body) = http(&stack.log.base, "GET", &path, None).expect("the log answers");
    assert_eq!(status, 200, "the log serves no Evidence Receipt for `{atl_entry_id}`");
    serde_json::from_slice(&body).expect("JSON")
}

/// The signed checkpoint the mirror publishes at a tree size.
fn signed_checkpoint(stack: &Stack, tree_size: u64) -> Value {
    let path = format!("/v1/checkpoints/{tree_size}");
    let (status, body) = http(&stack.mirror.base, "GET", &path, None).expect("the mirror answers");
    assert_eq!(status, 200, "the mirror publishes no checkpoint at tree size {tree_size}");
    serde_json::from_slice(&body).expect("JSON")
}

/// The entry envelopes the mirror serves for `[0, to)`.
fn corpus_envelopes(stack: &Stack, to: u64) -> Vec<Value> {
    let body = serde_json::to_vec(&json!({ "tree_size": to, "from_index": 0, "to_index": to }))
        .expect("serializable");
    let (status, response) =
        http(&stack.mirror.base, "POST", "/v1/range", Some(&body)).expect("the mirror answers");
    assert_eq!(status, 200, "the mirror refused a range over [0, {to})");
    let value: Value = serde_json::from_slice(&response).expect("JSON");
    value["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|entry| entry["envelope"].clone())
        .collect()
}

/// The leaves the tree-material file holds under a root.
fn leaves_of(trees: &Path, root: &str) -> Vec<Value> {
    let material: Value =
        serde_json::from_slice(&std::fs::read(trees).expect("the tree material")).expect("JSON");
    material
        .get(root)
        .and_then(|tree| tree.get("leaves"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}
