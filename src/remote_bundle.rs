//! Job-scoped CI bundles for artifacts and shared input predictions.
//!
//! The manifest is published after its immutable packs. Readers can keep using
//! the previous manifest during publication, and ordinary v3 lookups remain the
//! fallback for missing, oversized, or invalid entries.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::config::{Config, RemoteConfig};
use crate::prediction_share::{self, SharedPrediction};
use crate::remote::ManifestEntry;
use crate::remote_backend::RemoteBackend;
use crate::remote_pack::{self, CatalogEntry, CatalogPackRef, PackInputEntry};
use crate::store::Store;

const VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 64 << 20;
const MAX_PREDICTIONS: usize = 65_536;
const MAX_PACKS: usize = 4096;
const MAX_AGE_SECS: i64 = 7 * 24 * 60 * 60;
const INDEX_RESERVE: u64 = 1 << 20;
const MAX_ENTRIES_PER_PACK: usize = 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prediction {
    identity: String,
    crate_name: Option<String>,
    row: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    version: u32,
    key_schema: u32,
    job_key: String,
    created_at: i64,
    packs: Vec<CatalogPackRef>,
    predictions: Vec<Prediction>,
}

#[derive(Debug, Default)]
struct Report {
    packs: usize,
    entries: usize,
    predictions: usize,
    bytes: u64,
    skipped: usize,
}

fn manifest_key(prefix: &str, job_key: &str) -> Result<String> {
    ensure!(
        !job_key.trim().is_empty() && job_key.len() <= 4096,
        "invalid bundle job key"
    );
    let digest = blake3::hash(job_key.as_bytes());
    Ok(crate::config::join_remote_key(
        prefix,
        &format!("_manifests/bundles/{digest}.json.zst"),
    ))
}

fn decode_manifest(bytes: &[u8], job_key: &str, now: i64) -> Result<Bundle> {
    ensure!(
        bytes.len() as u64 <= MAX_MANIFEST_BYTES,
        "bundle manifest too large"
    );
    let mut decoder = zstd::stream::Decoder::new(bytes)?;
    decoder.window_log_max(27)?;
    let mut json = Vec::new();
    decoder
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut json)?;
    ensure!(
        json.len() as u64 <= MAX_MANIFEST_BYTES,
        "expanded bundle manifest too large"
    );
    let bundle: Bundle = serde_json::from_slice(&json)?;
    ensure!(bundle.version == VERSION, "unsupported bundle version");
    ensure!(
        bundle.key_schema == crate::cache_key::CACHE_KEY_VERSION,
        "bundle key schema mismatch"
    );
    ensure!(bundle.job_key == job_key, "bundle job key mismatch");
    ensure!(
        bundle.created_at <= now && now.saturating_sub(bundle.created_at) <= MAX_AGE_SECS,
        "expired or future bundle"
    );
    ensure!(bundle.packs.len() <= MAX_PACKS, "too many bundle packs");
    ensure!(
        bundle.predictions.len() <= MAX_PREDICTIONS,
        "too many bundle predictions"
    );
    let mut keys = HashSet::new();
    for pack in &bundle.packs {
        remote_pack::pack_object_key("", &pack.digest)?;
        ensure!(
            pack.pack_bytes > 0 && pack.pack_bytes <= remote_pack::DEFAULT_MAX_PACK_BYTES,
            "invalid bundle pack size"
        );
        ensure!(
            !pack.entries.is_empty() && pack.entries.len() <= MAX_ENTRIES_PER_PACK,
            "invalid bundle pack entry count"
        );
        for entry in &pack.entries {
            ensure!(
                crate::cache_key::is_valid_cache_key(&entry.cache_key)
                    && crate::cache_key::is_valid_cache_key(&entry.meta_digest)
                    && crate::cache_key::is_valid_crate_name(&entry.crate_name),
                "invalid bundle entry binding"
            );
            ensure!(keys.insert(&entry.cache_key), "duplicate bundle cache key");
        }
    }
    Ok(bundle)
}

/// Export only prediction rows that the individual-object publisher can share.
///
/// Local paths are relocated or refused by the existing conversion routines;
/// copying the prediction database itself would bypass that boundary.
fn export_predictions(
    config: &Config,
    registry: &Path,
    crates: &HashSet<&str>,
) -> Result<Vec<Prediction>> {
    let db = crate::store::open_index_db_readonly(&config.index_db_path())?;
    let mut stmt = db.prepare(
        "SELECT identity, crate_name, prediction_json FROM input_predictions
         WHERE length(prediction_json) <= 262144
           AND last_used >= unixepoch() - 604800
         ORDER BY last_used DESC, identity LIMIT 65536",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut predictions = Vec::new();
    let mut bytes = 0_u64;
    for row in rows {
        let (identity, crate_name, json) = row?;
        if crate_name
            .as_deref()
            .is_some_and(|name| !crates.contains(name))
        {
            continue;
        }
        let shared = if crate::cache_key::is_portable_identity(&identity) {
            serde_json::from_str(&json)
                .ok()
                .and_then(|row| prediction_share::for_remote_portable(&row, Some(registry)))
        } else if crate::cache_key::is_shared_target_identity(&identity) {
            serde_json::from_str(&json)
                .ok()
                .and_then(|row| prediction_share::for_remote_plain(&row, registry))
        } else {
            None
        };
        let Some(encoded) = shared.and_then(|row| prediction_share::encode(&identity, &row)) else {
            continue;
        };
        let prediction = Prediction {
            identity,
            crate_name,
            row: serde_json::from_slice(&encoded)?,
        };
        bytes += serde_json::to_vec(&prediction)?.len() as u64;
        if bytes > MAX_MANIFEST_BYTES / 2 {
            break;
        }
        predictions.push(prediction);
    }
    Ok(predictions)
}

fn import_predictions(
    store: &Store,
    registry: &Path,
    predictions: Vec<Prediction>,
) -> Result<usize> {
    let cache = store.file_hash_cache();
    let mut count = 0;
    for prediction in predictions {
        let bytes = serde_json::to_vec(&prediction.row)?;
        let Some(shared) = prediction_share::decode(&bytes, &prediction.identity) else {
            continue;
        };
        // Keep locally learned rows; their tree guards may be newer than the bundle.
        if cache.get_input_prediction(&prediction.identity)?.is_some() {
            continue;
        }
        let (schema, json) = match shared {
            SharedPrediction::Portable(row) => (row.schema, serde_json::to_string(&row)?),
            SharedPrediction::Plain(row) => {
                let Some(row) = prediction_share::plain_from_remote(&row, registry) else {
                    continue;
                };
                (row.schema, serde_json::to_string(&row)?)
            }
        };
        cache.put_input_prediction(
            &prediction.identity,
            schema,
            prediction.crate_name.as_deref(),
            &json,
        )?;
        count += 1;
    }
    Ok(count)
}

async fn upload_pack(
    backend: &dyn RemoteBackend,
    prefix: &str,
    inputs: Vec<PackInputEntry>,
) -> Result<CatalogPackRef> {
    let built = remote_pack::build_pack(prefix, inputs, remote_pack::DEFAULT_MAX_PACK_BYTES)?;
    let reference = CatalogPackRef {
        digest: built.digest,
        pack_bytes: built.bytes.len() as u64,
        entries: built
            .index
            .entries
            .into_iter()
            .map(|entry| CatalogEntry {
                cache_key: entry.cache_key,
                crate_name: entry.crate_name,
                meta_digest: entry.meta_digest,
            })
            .collect(),
    };
    backend
        .put(
            &built.object_key,
            built.bytes,
            Some(remote_pack::PACK_CONTENT_TYPE),
        )
        .await?;
    Ok(reference)
}

async fn save(
    backend: &dyn RemoteBackend,
    remote: &RemoteConfig,
    config: &Config,
    store: &Store,
    job_key: &str,
    registry: &Path,
    entries: &[ManifestEntry],
) -> Result<Report> {
    ensure!(
        !config.remote_readonly && !config.local_only,
        "bundle publication requires a writable remote"
    );
    let key = manifest_key(&remote.prefix, job_key)?;
    let mut report = Report::default();
    let mut bundle = Bundle {
        version: VERSION,
        key_schema: crate::cache_key::CACHE_KEY_VERSION,
        job_key: job_key.to_owned(),
        created_at: chrono::Utc::now().timestamp(),
        packs: Vec::new(),
        predictions: export_predictions(
            config,
            registry,
            &entries
                .iter()
                .map(|entry| entry.crate_name.as_str())
                .collect(),
        )?,
    };
    let mut inputs = Vec::new();
    let mut payload_bytes = 0_u64;
    let payload_cap = remote_pack::DEFAULT_MAX_PACK_BYTES - INDEX_RESERVE;
    for entry in entries {
        ensure!(
            crate::cache_key::is_valid_cache_key(&entry.cache_key),
            "invalid local cache key"
        );
        let Some(_lock) = store.try_lock(&entry.cache_key)? else {
            report.skipped += 1;
            continue;
        };
        let Some(meta) = store.stored_meta(&entry.cache_key) else {
            report.skipped += 1;
            continue;
        };
        // Leaves oversized entries on the individual-object download path.
        //
        // Checking their uncompressed size before packing bounds publisher memory.
        if entry.artifact_size > payload_cap
            || meta.files.iter().map(|file| file.size).sum::<u64>() > payload_cap
        {
            report.skipped += 1;
            continue;
        }
        let entry_dir = store.entry_dir(&entry.cache_key);
        let payload = match crate::remote_layout::create_entry_pack_zstd(
            &entry_dir,
            &config.store_dir().join("blobs"),
            &meta,
            3,
        ) {
            Ok(payload) if payload.len() as u64 <= payload_cap => payload,
            _ => {
                report.skipped += 1;
                continue;
            }
        };
        let meta_bytes = std::fs::read(entry_dir.join("meta.json"))?;
        let input = PackInputEntry {
            cache_key: entry.cache_key.clone(),
            crate_name: entry.crate_name.clone(),
            meta_digest: blake3::hash(&meta_bytes).to_hex().to_string(),
            payload,
        };
        if !inputs.is_empty()
            && (payload_bytes + input.payload.len() as u64 > payload_cap
                || inputs.len() >= MAX_ENTRIES_PER_PACK)
        {
            bundle
                .packs
                .push(upload_pack(backend, &remote.prefix, std::mem::take(&mut inputs)).await?);
            payload_bytes = 0;
        }
        ensure!(bundle.packs.len() < MAX_PACKS, "too many bundle packs");
        payload_bytes += input.payload.len() as u64;
        inputs.push(input);
    }
    if !inputs.is_empty() {
        bundle
            .packs
            .push(upload_pack(backend, &remote.prefix, inputs).await?);
    }
    report.packs = bundle.packs.len();
    report.entries = bundle.packs.iter().map(|pack| pack.entries.len()).sum();
    report.bytes = bundle.packs.iter().map(|pack| pack.pack_bytes).sum();
    report.predictions = bundle.predictions.len();
    ensure!(
        report.entries > 0 || report.predictions > 0,
        "no shareable bundle data; keeping previous manifest"
    );
    let json = serde_json::to_vec(&bundle)?;
    ensure!(
        json.len() as u64 <= MAX_MANIFEST_BYTES,
        "bundle manifest too large"
    );
    let compressed = zstd::stream::encode_all(json.as_slice(), 3)?;
    ensure!(
        compressed.len() as u64 <= MAX_MANIFEST_BYTES,
        "compressed bundle manifest too large"
    );
    backend
        .put(&key, compressed, Some("application/zstd"))
        .await?;
    Ok(report)
}

async fn restore(
    backend: &dyn RemoteBackend,
    remote: &RemoteConfig,
    store: &Store,
    job_key: &str,
    registry: &Path,
    max_bytes: u64,
) -> Result<Report> {
    let key = manifest_key(&remote.prefix, job_key)?;
    let Some(object) = backend.get(&key, Some(MAX_MANIFEST_BYTES)).await? else {
        eprintln!("No CI bundle for {job_key}; using ordinary cache lookups");
        return Ok(Report::default());
    };
    let bundle = decode_manifest(&object.body, job_key, chrono::Utc::now().timestamp())?;
    drop(object);
    let mut report = Report {
        predictions: import_predictions(store, registry, bundle.predictions)?,
        ..Default::default()
    };
    let mut budgeted_bytes = 0_u64;
    for pack in bundle.packs {
        if pack
            .entries
            .iter()
            .all(|entry| store.contains(&entry.cache_key))
        {
            continue;
        }
        if pack.pack_bytes > max_bytes.saturating_sub(budgeted_bytes) {
            report.skipped += pack.entries.len();
            continue;
        }
        // Charge attempted downloads as well as valid ones against the budget.
        budgeted_bytes += pack.pack_bytes;
        let result = async {
            let key = remote_pack::pack_object_key(&remote.prefix, &pack.digest)?;
            let object = backend
                .get(&key, Some(pack.pack_bytes))
                .await?
                .context("bundle pack missing")?;
            report.bytes += object.body.len() as u64;
            restore_pack(store, &pack, &object.body)
        }
        .await;
        match result {
            Ok(entries) => {
                report.entries += entries;
                report.packs += 1;
            }
            Err(error) => {
                report.skipped += pack.entries.len();
                tracing::warn!(
                    "CI bundle pack skipped; individual lookups remain available: {error:#}"
                );
            }
        }
    }
    Ok(report)
}

fn restore_pack(store: &Store, pack: &CatalogPackRef, body: &[u8]) -> Result<usize> {
    let decoded =
        remote_pack::decode_catalog_pack(body, pack, remote_pack::DEFAULT_MAX_PACK_BYTES)?;
    let mut imported = 0;
    for entry in decoded.entries {
        let key = &entry.descriptor.cache_key;
        let Some(_lock) = store.try_lock(key)? else {
            continue;
        };
        if store.contains(key) {
            continue;
        }
        let extracted = crate::remote_layout::extract_verified_prefetch_entry(
            key,
            &entry.descriptor.crate_name,
            &entry.descriptor.meta_digest,
            entry.payload,
            &store.entry_dir(key),
            None,
        );
        match extracted {
            Ok(extracted) => {
                if let Err(error) = store.import_verified_restored_entries(&[extracted.restored]) {
                    store.discard_uncommitted_restored_entry(key)?;
                    return Err(error);
                }
                imported += 1;
            }
            Err(error) => {
                store.discard_uncommitted_restored_entry(key)?;
                return Err(error);
            }
        }
    }
    Ok(imported)
}

fn automatic_key(
    enabled: Option<&str>,
    explicit: Option<&str>,
    environment: Option<&str>,
) -> Option<String> {
    if !matches!(enabled, Some("true" | "1")) {
        return None;
    }
    explicit
        .or(environment)
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
}

fn configured_key(explicit: Option<&str>) -> Option<String> {
    automatic_key(
        std::env::var("KACHE_CI_BUNDLES").ok().as_deref(),
        explicit,
        std::env::var("KACHE_MANIFEST_KEY").ok().as_deref(),
    )
}

/// Restores a CI bundle before an explicitly requested daemon start.
///
/// Cache actions already start the daemon after exporting the job's manifest
/// key. Keeping this hook out of wrapper-driven starts avoids repeated warmups.
pub(crate) fn restore_before_start(config: &Config) {
    let Some(key) = configured_key(None) else {
        return;
    };
    if config.remote.is_none() || config.local_only {
        return;
    }
    match crate::daemon::is_running(config) {
        Ok(false) => {
            if let Err(error) = run(config, &key, Some(10 << 30)) {
                eprintln!("warning: CI bundle restore skipped; using ordinary lookups: {error:#}");
            }
        }
        Ok(true) => {}
        Err(error) => {
            eprintln!("warning: CI bundle warmup could not check daemon state: {error:#}")
        }
    }
}

/// Publishes a CI bundle after an explicit build-manifest save.
///
/// The cache action already uses this command in its post hook. Draining the
/// daemon makes its artifacts durable before the bundle snapshots the store.
pub(crate) fn save_after_manifest(config: &Config, explicit_key: Option<&str>) {
    let Some(key) = configured_key(explicit_key) else {
        return;
    };
    if config.remote.is_none() || config.remote_readonly || config.local_only {
        return;
    }
    let result =
        crate::daemon::send_shutdown_request(config).and_then(|()| run(config, &key, None));
    if let Err(error) = result {
        eprintln!("warning: CI bundle publication skipped; keeping previous bundle: {error:#}");
    }
}

pub(crate) fn run(config: &Config, job_key: &str, restore_max_bytes: Option<u64>) -> Result<()> {
    let remote = config.remote.as_ref().context("no remote configured")?;
    manifest_key(&remote.prefix, job_key)?;
    if config.local_only {
        bail!("CI bundles require remote access");
    }
    if restore_max_bytes.is_none() && config.remote_readonly {
        bail!("bundle publication requires a writable remote");
    }
    ensure!(
        config.readonly_store.is_none(),
        "CI bundles require a writable local store"
    );
    // Requires the daemon to drain before bundle imports or publication.
    //
    // Bundle imports must not race its in-process download claims.
    ensure!(
        !crate::daemon::is_running(config)?,
        "stop the daemon before using CI bundles (kache daemon stop)"
    );
    let store = Store::open(config)?;
    let registry = home::cargo_home()?.join("registry/src");
    let entries = if restore_max_bytes.is_none() {
        crate::cli::manifest_entries_from_events(
            &crate::events::read_events(&config.event_log_path())?,
            None,
        )
    } else {
        Vec::new()
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = runtime.block_on(async {
        let backend = crate::remote_backend::create_backend_for(
            remote,
            config.pull_request_prefix.as_deref(),
            config.s3_pool_idle_secs,
        )
        .await?;
        match restore_max_bytes {
            Some(max_bytes) => {
                restore(
                    backend.as_ref(),
                    remote,
                    &store,
                    job_key,
                    &registry,
                    max_bytes,
                )
                .await
            }
            None => {
                save(
                    backend.as_ref(),
                    remote,
                    config,
                    &store,
                    job_key,
                    &registry,
                    &entries,
                )
                .await
            }
        }
    })?;
    eprintln!(
        "CI bundle: {} packs, {} entries, {} predictions, {} compressed bytes, {} entries skipped",
        report.packs, report.entries, report.predictions, report.bytes, report.skipped
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_backend::{GetObject, memory_backend};
    use std::ffi::OsString;
    use std::sync::Mutex;

    struct RecordingBackend {
        inner: crate::remote_backend::OpenDalBackend,
        gets: Mutex<Vec<String>>,
        fail_pack_put: bool,
        missing_packs: bool,
    }

    impl RecordingBackend {
        fn new() -> Self {
            Self {
                inner: memory_backend(),
                gets: Mutex::new(Vec::new()),
                fail_pack_put: false,
                missing_packs: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl RemoteBackend for RecordingBackend {
        async fn head(&self, key: &str) -> Result<bool> {
            self.inner.head(key).await
        }
        async fn get(&self, key: &str, max_bytes: Option<u64>) -> Result<Option<GetObject>> {
            self.gets.lock().unwrap().push(key.to_owned());
            if self.missing_packs && key.ends_with(".kpack") {
                return Ok(None);
            }
            self.inner.get(key, max_bytes).await
        }
        async fn put(&self, key: &str, body: Vec<u8>, content_type: Option<&str>) -> Result<()> {
            if self.fail_pack_put && key.ends_with(".kpack") {
                bail!("injected upload failure");
            }
            self.inner.put(key, body, content_type).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>> {
            self.inner.list(prefix).await
        }
        fn describe(&self, key: &str) -> String {
            self.inner.describe(key)
        }
    }

    fn config(root: &Path) -> Config {
        let env = crate::invocation::InvocationEnv::from_parts(
            [(OsString::from("KACHE_HOST_CONFIG"), OsString::new())],
            Some(root.to_owned()),
            Some(root.join("home")),
            root.join("tmp"),
        );
        let mut config = Config::load_for(&env).unwrap();
        config.cache_dir = root.join("cache");
        config.remote_readonly = false;
        config.local_only = false;
        config
    }

    fn seed(store: &Store, root: &Path, name: &str) -> ManifestEntry {
        let key = blake3::hash(name.as_bytes()).to_hex().to_string();
        let file = root.join(format!("lib{name}.rlib"));
        std::fs::write(&file, format!("compiled artifact for {name}")).unwrap();
        let size = std::fs::metadata(&file).unwrap().len();
        store
            .put(
                &key,
                name,
                &["rlib".into()],
                &[],
                "test-target",
                "dev",
                &[(file, format!("lib{name}.rlib"))],
                "",
                "",
            )
            .unwrap();
        ManifestEntry {
            cache_key: key,
            crate_name: name.into(),
            compile_time_ms: 100,
            artifact_size: size,
        }
    }

    fn row() -> crate::cache_key::PortablePrediction {
        crate::cache_key::PortablePrediction {
            schema: crate::cache_key::PORTABLE_PREDICTION_SCHEMA,
            sources: vec![crate::cache_key::Portable::Workspace("/src/lib.rs".into())],
            env_deps: vec![],
            tree: "workspace-tree".into(),
        }
    }

    fn seed_prediction(store: &Store, identity: &str) {
        let row = row();
        store
            .file_hash_cache()
            .put_input_prediction(
                identity,
                row.schema,
                Some("one"),
                &serde_json::to_string(&row).unwrap(),
            )
            .unwrap();
    }

    async fn manifest(backend: &dyn RemoteBackend) -> Bundle {
        let obj = backend
            .get(&manifest_key("prefix", "job").unwrap(), None)
            .await
            .unwrap()
            .unwrap();
        decode_manifest(&obj.body, "job", chrono::Utc::now().timestamp()).unwrap()
    }

    #[tokio::test]
    async fn round_trip_restores_two_artifacts_and_prediction_in_two_gets() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let config = config(src.path());
        let store = Store::open(&config).unwrap();
        let target = Store::open(&self::config(dst.path())).unwrap();
        let entries = vec![
            seed(&store, src.path(), "one"),
            seed(&store, src.path(), "two"),
        ];
        seed_prediction(&store, "shared-workspace-v1:portable");
        let backend = RecordingBackend::new();
        let remote = RemoteConfig::test_s3("bucket", "prefix");
        let report = save(
            &backend,
            &remote,
            &config,
            &store,
            "job",
            src.path(),
            &entries,
        )
        .await
        .unwrap();
        assert_eq!(
            (report.packs, report.entries, report.predictions),
            (1, 2, 1)
        );
        let restored = restore(&backend, &remote, &target, "job", dst.path(), 1 << 30)
            .await
            .unwrap();
        assert_eq!(
            (restored.packs, restored.entries, restored.predictions),
            (1, 2, 1)
        );
        assert_eq!(
            backend.gets.lock().unwrap().len(),
            2,
            "one manifest and one artifact pack GET"
        );
        for entry in &entries {
            let meta = target.get(&entry.cache_key).unwrap().unwrap();
            assert_eq!(meta, store.get(&entry.cache_key).unwrap().unwrap());
            assert!(target.contains(&entry.cache_key));
        }
        let prediction = target
            .file_hash_cache()
            .get_input_prediction("shared-workspace-v1:portable")
            .unwrap()
            .unwrap();
        assert_eq!(prediction.1, serde_json::to_string(&row()).unwrap());
        let warm = restore(&backend, &remote, &target, "job", dst.path(), 1 << 30)
            .await
            .unwrap();
        assert_eq!((warm.packs, warm.entries, warm.predictions), (0, 0, 0));
        assert_eq!(
            backend.gets.lock().unwrap().len(),
            3,
            "warm cache needs only the manifest"
        );
    }

    #[tokio::test]
    async fn corrupt_or_missing_pack_preserves_prediction_restore_and_demand_fallback() {
        for corrupt in [false, true] {
            let src = tempfile::tempdir().unwrap();
            let dst = tempfile::tempdir().unwrap();
            let config = config(src.path());
            let store = Store::open(&config).unwrap();
            let target = Store::open(&self::config(dst.path())).unwrap();
            let entry = seed(&store, src.path(), "one");
            seed_prediction(&store, "shared-workspace-v1:portable");
            let mut backend = RecordingBackend::new();
            let remote = RemoteConfig::test_s3("bucket", "prefix");
            save(
                &backend,
                &remote,
                &config,
                &store,
                "job",
                src.path(),
                std::slice::from_ref(&entry),
            )
            .await
            .unwrap();
            let manifest = manifest(&backend).await;
            let key = remote_pack::pack_object_key("prefix", &manifest.packs[0].digest).unwrap();
            if corrupt {
                backend.put(&key, b"corrupt".to_vec(), None).await.unwrap();
            } else {
                backend.missing_packs = true;
            }
            let report = restore(&backend, &remote, &target, "job", dst.path(), 1 << 30)
                .await
                .unwrap();
            assert_eq!(
                (report.entries, report.predictions, report.skipped),
                (0, 1, 1)
            );
            assert!(!target.contains(&entry.cache_key));
            assert!(
                !target
                    .entry_dir(&entry.cache_key)
                    .join("meta.json")
                    .exists()
            );
        }
    }

    #[tokio::test]
    async fn byte_budget_skips_packs_without_losing_predictions() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let config = config(src.path());
        let store = Store::open(&config).unwrap();
        let target = Store::open(&self::config(dst.path())).unwrap();
        let entry = seed(&store, src.path(), "one");
        seed_prediction(&store, "shared-workspace-v1:portable");
        let backend = RecordingBackend::new();
        let remote = RemoteConfig::test_s3("bucket", "prefix");
        save(
            &backend,
            &remote,
            &config,
            &store,
            "job",
            src.path(),
            std::slice::from_ref(&entry),
        )
        .await
        .unwrap();
        let report = restore(&backend, &remote, &target, "job", dst.path(), 0)
            .await
            .unwrap();
        assert_eq!(
            (
                report.entries,
                report.predictions,
                report.bytes,
                report.skipped
            ),
            (0, 1, 0, 1)
        );
        assert_eq!(backend.gets.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn failed_publication_keeps_previous_manifest_and_readonly_never_writes() {
        let src = tempfile::tempdir().unwrap();
        let mut config = config(src.path());
        let store = Store::open(&config).unwrap();
        let entry = seed(&store, src.path(), "one");
        let mut backend = RecordingBackend::new();
        let remote = RemoteConfig::test_s3("bucket", "prefix");
        let key = manifest_key("prefix", "job").unwrap();
        backend.put(&key, b"previous".to_vec(), None).await.unwrap();
        backend.fail_pack_put = true;
        assert!(
            save(
                &backend,
                &remote,
                &config,
                &store,
                "job",
                src.path(),
                std::slice::from_ref(&entry)
            )
            .await
            .is_err()
        );
        assert_eq!(
            backend
                .get(&key, None)
                .await
                .unwrap()
                .unwrap()
                .body
                .as_ref(),
            b"previous"
        );
        config.remote_readonly = true;
        backend.fail_pack_put = false;
        assert!(
            save(
                &backend,
                &remote,
                &config,
                &store,
                "other",
                src.path(),
                &[entry]
            )
            .await
            .is_err()
        );
        assert!(
            !backend
                .head(&manifest_key("prefix", "other").unwrap())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn missing_bundle_is_a_clean_miss() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&config(dir.path())).unwrap();
        let report = restore(
            &RecordingBackend::new(),
            &RemoteConfig::test_s3("bucket", "prefix"),
            &store,
            "unknown",
            dir.path(),
            100,
        )
        .await
        .unwrap();
        assert_eq!((report.entries, report.packs), (0, 0));
    }

    #[test]
    fn predictions_refuse_private_paths_and_identity_swaps_and_keep_local_rows() {
        let src = tempfile::tempdir().unwrap();
        let config = config(src.path());
        let store = Store::open(&config).unwrap();
        seed_prediction(&store, "shared-workspace-v1:valid");
        let mut private = row();
        private.sources = vec![crate::cache_key::Portable::Literal(
            "/private/source.rs".into(),
        )];
        store
            .file_hash_cache()
            .put_input_prediction(
                "shared-workspace-v1:private",
                private.schema,
                Some("one"),
                &serde_json::to_string(&private).unwrap(),
            )
            .unwrap();
        seed_prediction(&store, "machine-local-only");
        let rows = export_predictions(&config, src.path(), &HashSet::from(["one"])).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].identity, "shared-workspace-v1:valid");
        assert_eq!(import_predictions(&store, src.path(), rows).unwrap(), 0);
        let mut rows = export_predictions(&config, src.path(), &HashSet::from(["one"])).unwrap();
        rows[0].identity = "shared-workspace-v1:swapped".into();
        assert_eq!(import_predictions(&store, src.path(), rows).unwrap(), 0);
        assert!(
            store
                .file_hash_cache()
                .get_input_prediction("shared-workspace-v1:swapped")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn large_job_splits_into_packs_and_restores_only_the_remaining_pack() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let config = config(src.path());
        let store = Store::open(&config).unwrap();
        let target = Store::open(&self::config(dst.path())).unwrap();
        let entries = (0..1025)
            .map(|index| seed(&store, src.path(), &format!("crate{index}")))
            .collect::<Vec<_>>();
        let backend = RecordingBackend::new();
        let remote = RemoteConfig::test_s3("bucket", "prefix");
        let published = save(
            &backend,
            &remote,
            &config,
            &store,
            "job",
            src.path(),
            &entries,
        )
        .await
        .unwrap();
        assert_eq!(published.packs, 2);
        let first_pack_bytes = manifest(&backend).await.packs[0].pack_bytes;
        backend.gets.lock().unwrap().clear();
        let first = restore(
            &backend,
            &remote,
            &target,
            "job",
            dst.path(),
            first_pack_bytes,
        )
        .await
        .unwrap();
        assert_eq!(
            (first.packs, first.entries, first.skipped, first.bytes),
            (1, 1024, 1, first_pack_bytes)
        );
        let second = restore(&backend, &remote, &target, "job", dst.path(), 1 << 30)
            .await
            .unwrap();
        assert_eq!((second.packs, second.entries, second.skipped), (1, 1, 0));
        assert_eq!(
            backend.gets.lock().unwrap().len(),
            4,
            "two manifests and each pack exactly once"
        );
        assert!(
            entries
                .iter()
                .all(|entry| target.contains(&entry.cache_key))
        );
    }

    #[tokio::test]
    async fn pr_bundle_writes_and_reads_stay_inside_the_pr_view() {
        let remote_dir = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let config = config(src.path());
        let store = Store::open(&config).unwrap();
        let target = Store::open(&self::config(dst.path())).unwrap();
        let entry = seed(&store, src.path(), "one");
        let remote = RemoteConfig {
            prefix: "protected".into(),
            backend: crate::config::RemoteBackendConfig::Filesystem(
                crate::config::FilesystemRemoteConfig {
                    root: remote_dir.path().to_owned(),
                    atomic_write_dir: remote_dir.path().join("staging"),
                },
            ),
        };
        let pr = crate::remote_backend::create_backend_for(&remote, Some("prs"), 30)
            .await
            .unwrap();
        let protected = crate::remote_backend::create_backend_for(&remote, None, 30)
            .await
            .unwrap();
        save(
            pr.as_ref(),
            &remote,
            &config,
            &store,
            "job",
            src.path(),
            std::slice::from_ref(&entry),
        )
        .await
        .unwrap();
        assert!(
            !protected
                .head(&manifest_key("protected", "job").unwrap())
                .await
                .unwrap()
        );
        assert!(
            protected
                .head(&manifest_key("prs", "job").unwrap())
                .await
                .unwrap()
        );
        let trusted = restore(
            protected.as_ref(),
            &remote,
            &target,
            "job",
            dst.path(),
            1 << 30,
        )
        .await
        .unwrap();
        assert_eq!(trusted.entries, 0);
        let untrusted = restore(pr.as_ref(), &remote, &target, "job", dst.path(), 1 << 30)
            .await
            .unwrap();
        assert_eq!(untrusted.entries, 1);
        assert!(target.contains(&entry.cache_key));
    }

    #[test]
    fn plain_predictions_relocate_registry_paths_on_import() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let config = config(src.path());
        let store = Store::open(&config).unwrap();
        let target = Store::open(&self::config(dst.path())).unwrap();
        let identity = "shared-target-v2:registry";
        let row = crate::cache_key::InputPrediction {
            schema: crate::cache_key::PREDICTION_SCHEMA,
            sources: vec![src.path().join("index/one/src/lib.rs")],
            env_deps: vec![],
            tree: None,
        };
        store
            .file_hash_cache()
            .put_input_prediction(
                identity,
                row.schema,
                Some("one"),
                &serde_json::to_string(&row).unwrap(),
            )
            .unwrap();
        let exported = export_predictions(&config, src.path(), &HashSet::from(["one"])).unwrap();
        assert_eq!(exported.len(), 1);
        assert!(
            !serde_json::to_string(&exported)
                .unwrap()
                .contains(src.path().to_str().unwrap())
        );
        assert_eq!(
            import_predictions(&target, dst.path(), exported).unwrap(),
            1
        );
        let (_, json) = target
            .file_hash_cache()
            .get_input_prediction(identity)
            .unwrap()
            .unwrap();
        let restored: crate::cache_key::InputPrediction = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.sources, [dst.path().join("index/one/src/lib.rs")]);
    }

    #[test]
    fn automatic_bundles_require_opt_in_and_a_stable_job_key() {
        assert_eq!(automatic_key(None, Some("job"), None), None);
        assert_eq!(automatic_key(Some("false"), None, Some("job")), None);
        assert_eq!(automatic_key(Some("true"), None, None), None);
        assert_eq!(automatic_key(Some("true"), None, Some("  ")), None);
        assert_eq!(
            automatic_key(Some("true"), None, Some(" job ")),
            Some("job".into())
        );
        assert_eq!(
            automatic_key(Some("1"), Some("explicit"), Some("environment")),
            Some("explicit".into())
        );
    }

    #[test]
    fn manifest_binds_job_schema_time_and_safe_pack_references() {
        let mut bundle = Bundle {
            version: VERSION,
            key_schema: crate::cache_key::CACHE_KEY_VERSION,
            job_key: "job".into(),
            created_at: 1_000_000,
            packs: vec![],
            predictions: vec![],
        };
        let encode = |bundle: &Bundle| {
            zstd::stream::encode_all(serde_json::to_vec(bundle).unwrap().as_slice(), 1).unwrap()
        };
        assert!(decode_manifest(&encode(&bundle), "job", 1_000_000).is_ok());
        assert!(decode_manifest(&encode(&bundle), "other", 1_000_000).is_err());
        assert!(decode_manifest(&encode(&bundle), "job", 999_999).is_err());
        assert!(decode_manifest(&encode(&bundle), "job", 1_604_801).is_err());
        bundle.version = 99;
        assert!(decode_manifest(&encode(&bundle), "job", 1_000_000).is_err());
        bundle.version = VERSION;
        bundle.key_schema += 1;
        assert!(decode_manifest(&encode(&bundle), "job", 1_000_000).is_err());
        bundle.key_schema = crate::cache_key::CACHE_KEY_VERSION;
        bundle.packs.push(CatalogPackRef {
            digest: "../escape".into(),
            pack_bytes: 1,
            entries: vec![],
        });
        assert!(decode_manifest(&encode(&bundle), "job", 1_000_000).is_err());
        assert!(manifest_key("prefix", " ").is_err());
        assert!(!manifest_key("prefix", "../../job").unwrap().contains(".."));
    }
}
