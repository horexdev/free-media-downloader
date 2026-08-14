use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::error::CoreError;
use crate::job::{JobId, JobSnapshot, JobState};

const DATABASE_SCHEMA_VERSION: i64 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SftpHostKeyRecord {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub raw_key_base64: String,
    pub fingerprint_sha256: String,
    pub first_seen: String,
    pub last_verified: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackConsentRecord {
    pub pack_id: String,
    pub manifest_sha256: String,
    pub license_digest: String,
    pub accepted_size: u64,
    pub auto_update: bool,
    pub accepted_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateReceipt {
    pub target_name: String,
    pub version: String,
    pub security_sequence: u64,
    pub length: u64,
    pub sha256: String,
    pub metadata_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateJournalRecord {
    pub transaction_id: String,
    pub state: String,
    pub journal_json: String,
    pub updated_at: String,
}

#[derive(Clone)]
pub struct JobStore {
    connection: Arc<Mutex<Connection>>,
}

impl JobStore {
    pub fn open(path: &Path) -> Result<Self, CoreError> {
        let connection = Connection::open(path)?;
        Self::initialize(connection)
    }

    pub fn open_in_memory() -> Result<Self, CoreError> {
        Self::initialize(Connection::open_in_memory()?)
    }

    fn initialize(mut connection: Connection) -> Result<Self, CoreError> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let schema_version: i64 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if schema_version > DATABASE_SCHEMA_VERSION {
            return Err(CoreError::Storage(rusqlite::Error::InvalidQuery));
        }
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY NOT NULL,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY NOT NULL,
                state TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS jobs_updated_at ON jobs(updated_at DESC);
            CREATE TABLE IF NOT EXISTS pack_active (
                pack_id TEXT PRIMARY KEY NOT NULL,
                version TEXT NOT NULL,
                target TEXT NOT NULL,
                security_sequence INTEGER NOT NULL,
                manifest_sha256 TEXT NOT NULL,
                activated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pack_security_high_water (
                pack_id TEXT PRIMARY KEY NOT NULL,
                security_sequence INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pack_consents (
                pack_id TEXT PRIMARY KEY NOT NULL,
                manifest_sha256 TEXT NOT NULL,
                license_digest TEXT NOT NULL,
                accepted_size INTEGER NOT NULL,
                auto_update INTEGER NOT NULL DEFAULT 0,
                accepted_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pack_activation_history (
                pack_id TEXT NOT NULL,
                version TEXT NOT NULL,
                target TEXT NOT NULL,
                security_sequence INTEGER NOT NULL,
                manifest_sha256 TEXT NOT NULL,
                activated_at TEXT NOT NULL,
                PRIMARY KEY (pack_id, version, target, manifest_sha256)
            );
            CREATE TABLE IF NOT EXISTS engine_leases (
                job_id TEXT NOT NULL,
                pack_id TEXT NOT NULL,
                version TEXT NOT NULL,
                target TEXT NOT NULL,
                acquired_at TEXT NOT NULL,
                PRIMARY KEY (job_id, pack_id)
            );
            CREATE TABLE IF NOT EXISTS job_attempts (
                job_id TEXT NOT NULL,
                attempt INTEGER NOT NULL,
                engine_id TEXT NOT NULL,
                pack_version TEXT NOT NULL,
                staging_path TEXT NOT NULL,
                state TEXT NOT NULL,
                error_code TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (job_id, attempt)
            );
            CREATE TABLE IF NOT EXISTS resume_metadata (
                job_id TEXT PRIMARY KEY NOT NULL,
                partial_path TEXT NOT NULL,
                downloaded_bytes INTEGER NOT NULL,
                validator TEXT,
                remote_size INTEGER,
                remote_modified_at TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trusted_sftp_keys (
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                algorithm TEXT NOT NULL,
                raw_key_base64 TEXT NOT NULL,
                fingerprint_sha256 TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_verified TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (host, port, algorithm, raw_key_base64)
            );
            CREATE TABLE IF NOT EXISTS update_journals (
                transaction_id TEXT PRIMARY KEY NOT NULL,
                state TEXT NOT NULL,
                journal_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS update_receipts (
                target_name TEXT PRIMARY KEY NOT NULL,
                version TEXT NOT NULL,
                security_sequence INTEGER NOT NULL,
                length INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            PRAGMA user_version = 3;
            ",
        )?;
        transaction.commit()?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn save(&self, job: &JobSnapshot) -> Result<(), CoreError> {
        let json = serde_json::to_string(job)?;
        self.connection.lock().execute(
            "
            INSERT INTO jobs (id, state, snapshot_json, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(id) DO UPDATE SET
                state = excluded.state,
                snapshot_json = excluded.snapshot_json,
                updated_at = excluded.updated_at
            ",
            params![
                job.id.to_string(),
                serde_json::to_string(&job.state)?,
                json,
                job.created_at.to_rfc3339(),
                job.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get(&self, id: JobId) -> Result<Option<JobSnapshot>, CoreError> {
        let json = self
            .connection
            .lock()
            .query_row(
                "SELECT snapshot_json FROM jobs WHERE id = ?1",
                [id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        json.map(|value| serde_json::from_str(&value).map_err(CoreError::from))
            .transpose()
    }

    pub fn list(&self) -> Result<Vec<JobSnapshot>, CoreError> {
        let connection = self.connection.lock();
        let mut statement = connection
            .prepare("SELECT snapshot_json FROM jobs ORDER BY datetime(updated_at) DESC, id ASC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut jobs = Vec::new();
        for row in rows {
            jobs.push(serde_json::from_str(&row?)?);
        }
        Ok(jobs)
    }

    pub fn mark_active_jobs_interrupted(&self) -> Result<usize, CoreError> {
        let jobs = self.list()?;
        let mut changed = 0;
        for mut job in jobs {
            if matches!(
                job.state,
                JobState::Preparing | JobState::Downloading | JobState::PostProcessing
            ) {
                job.state = JobState::Interrupted;
                job.updated_at = chrono::Utc::now();
                self.save(&job)?;
                changed += 1;
            }
        }
        Ok(changed)
    }

    pub fn pack_security_high_water(&self, pack_id: &str) -> Result<u64, CoreError> {
        let value = self
            .connection
            .lock()
            .query_row(
                "SELECT security_sequence FROM pack_security_high_water WHERE pack_id = ?1",
                [pack_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        value
            .unwrap_or(0)
            .try_into()
            .map_err(|_| CoreError::SupplyChain("negative pack security sequence".into()))
    }

    pub fn advance_pack_security_high_water(
        &self,
        pack_id: &str,
        security_sequence: u64,
    ) -> Result<(), CoreError> {
        let current = self.pack_security_high_water(pack_id)?;
        if security_sequence < current {
            return Err(CoreError::SupplyChain(
                "pack security sequence rollback was rejected".into(),
            ));
        }
        let value = i64::try_from(security_sequence)
            .map_err(|_| CoreError::SupplyChain("security sequence is too large".into()))?;
        self.connection.lock().execute(
            "
            INSERT INTO pack_security_high_water (pack_id, security_sequence)
            VALUES (?1, ?2)
            ON CONFLICT(pack_id) DO UPDATE SET security_sequence = MAX(security_sequence, excluded.security_sequence)
            ",
            params![pack_id, value],
        )?;
        Ok(())
    }

    pub fn record_pack_activation(
        &self,
        pointer: &crate::pack::ActivationPointer,
    ) -> Result<(), CoreError> {
        self.commit_pack_activation(pointer)
    }

    pub fn commit_pack_activation(
        &self,
        pointer: &crate::pack::ActivationPointer,
    ) -> Result<(), CoreError> {
        let target = pointer.target.to_string();
        let sequence = i64::try_from(pointer.security_sequence).map_err(|_| {
            CoreError::SupplyChain("pack security sequence exceeds SQLite range".into())
        })?;
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;
        let current = transaction
            .query_row(
                "SELECT security_sequence FROM pack_security_high_water WHERE pack_id = ?1",
                [&pointer.pack_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0);
        if sequence < current {
            return Err(CoreError::SupplyChain(
                "pack security sequence rollback was rejected".into(),
            ));
        }
        transaction.execute(
            "
            INSERT INTO pack_security_high_water (pack_id, security_sequence)
            VALUES (?1, ?2)
            ON CONFLICT(pack_id) DO UPDATE SET
                security_sequence = MAX(security_sequence, excluded.security_sequence)
            ",
            params![pointer.pack_id, sequence],
        )?;
        transaction.execute(
            "
            INSERT INTO pack_active
                (pack_id, version, target, security_sequence, manifest_sha256, activated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))
            ON CONFLICT(pack_id) DO UPDATE SET
                version = excluded.version,
                target = excluded.target,
                security_sequence = excluded.security_sequence,
                manifest_sha256 = excluded.manifest_sha256,
                activated_at = excluded.activated_at
            ",
            params![
                pointer.pack_id,
                pointer.version,
                target,
                sequence,
                pointer.manifest_sha256,
            ],
        )?;
        transaction.execute(
            "
            INSERT INTO pack_activation_history
                (pack_id, version, target, security_sequence, manifest_sha256, activated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))
            ON CONFLICT(pack_id, version, target, manifest_sha256) DO UPDATE SET
                activated_at = excluded.activated_at
            ",
            params![
                pointer.pack_id,
                pointer.version,
                target,
                sequence,
                pointer.manifest_sha256,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn acquire_engine_lease(
        &self,
        job_id: JobId,
        pack_id: &str,
        version: &str,
        target: &str,
    ) -> Result<(), CoreError> {
        self.connection.lock().execute(
            "
            INSERT INTO engine_leases (job_id, pack_id, version, target, acquired_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(job_id, pack_id) DO UPDATE SET
                version = excluded.version,
                target = excluded.target,
                acquired_at = excluded.acquired_at
            ",
            params![
                job_id.to_string(),
                pack_id,
                version,
                target,
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn release_engine_leases(&self, job_id: JobId) -> Result<usize, CoreError> {
        Ok(self.connection.lock().execute(
            "DELETE FROM engine_leases WHERE job_id = ?1",
            [job_id.to_string()],
        )?)
    }

    pub fn leased_pack_versions(&self) -> Result<BTreeSet<(String, String, String)>, CoreError> {
        let connection = self.connection.lock();
        let mut statement = connection.prepare(
            "SELECT pack_id, version, target FROM engine_leases ORDER BY pack_id, version, target",
        )?;
        let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        let mut leases = BTreeSet::new();
        for row in rows {
            leases.insert(row?);
        }
        Ok(leases)
    }

    pub fn save_pack_consent(&self, consent: &PackConsentRecord) -> Result<(), CoreError> {
        crate::engine::validate_component(&consent.pack_id)?;
        if !is_sha256(&consent.manifest_sha256) || !is_sha256(&consent.license_digest) {
            return Err(CoreError::SupplyChain(
                "pack consent contains an invalid digest".into(),
            ));
        }
        let accepted_size = i64::try_from(consent.accepted_size)
            .map_err(|_| CoreError::SupplyChain("pack consent size is too large".into()))?;
        self.connection.lock().execute(
            "
            INSERT INTO pack_consents (
                pack_id, manifest_sha256, license_digest, accepted_size,
                auto_update, accepted_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(pack_id) DO UPDATE SET
                manifest_sha256 = excluded.manifest_sha256,
                license_digest = excluded.license_digest,
                accepted_size = excluded.accepted_size,
                auto_update = excluded.auto_update,
                accepted_at = excluded.accepted_at,
                updated_at = excluded.updated_at
            ",
            params![
                consent.pack_id,
                consent.manifest_sha256,
                consent.license_digest,
                accepted_size,
                consent.auto_update,
                consent.accepted_at,
                consent.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn pack_consent(&self, pack_id: &str) -> Result<Option<PackConsentRecord>, CoreError> {
        self.connection
            .lock()
            .query_row(
                "
                SELECT pack_id, manifest_sha256, license_digest, accepted_size,
                       auto_update, accepted_at, updated_at
                FROM pack_consents WHERE pack_id = ?1
                ",
                [pack_id],
                |row| {
                    let accepted_size: i64 = row.get(3)?;
                    Ok(PackConsentRecord {
                        pack_id: row.get(0)?,
                        manifest_sha256: row.get(1)?,
                        license_digest: row.get(2)?,
                        accepted_size: accepted_size.try_into().map_err(|_| {
                            rusqlite::Error::IntegralValueOutOfRange(3, accepted_size)
                        })?,
                        auto_update: row.get(4)?,
                        accepted_at: row.get(5)?,
                        updated_at: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(CoreError::from)
    }

    pub fn save_update_receipt(&self, receipt: &UpdateReceipt) -> Result<(), CoreError> {
        if receipt.target_name.trim().is_empty()
            || receipt.version.trim().is_empty()
            || receipt.length == 0
            || !is_sha256(&receipt.sha256)
            || serde_json::from_str::<serde_json::Value>(&receipt.metadata_json).is_err()
        {
            return Err(CoreError::SupplyChain(
                "update receipt contains invalid authorization data".into(),
            ));
        }
        let sequence = i64::try_from(receipt.security_sequence)
            .map_err(|_| CoreError::SupplyChain("update sequence is too large".into()))?;
        let length = i64::try_from(receipt.length)
            .map_err(|_| CoreError::SupplyChain("update artifact is too large".into()))?;
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT version, security_sequence, length, sha256, metadata_json, created_at
                 FROM update_receipts WHERE target_name = ?1",
                [&receipt.target_name],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?;
        if let Some((version, current_sequence, current_length, sha256, metadata, _created_at)) =
            existing
        {
            if sequence < current_sequence {
                return Err(CoreError::SupplyChain(
                    "update receipt rollback was rejected".into(),
                ));
            }
            if sequence == current_sequence {
                let exact_replay = version == receipt.version
                    && current_length == length
                    && sha256.eq_ignore_ascii_case(&receipt.sha256)
                    && metadata == receipt.metadata_json;
                if exact_replay {
                    return Ok(());
                }
                return Err(CoreError::SupplyChain(
                    "update receipt sequence was replayed with different content".into(),
                ));
            }
        }
        transaction.execute(
            "
            INSERT INTO update_receipts
                (target_name, version, security_sequence, length, sha256, metadata_json, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(target_name) DO UPDATE SET
                version = excluded.version,
                security_sequence = excluded.security_sequence,
                length = excluded.length,
                sha256 = excluded.sha256,
                metadata_json = excluded.metadata_json,
                created_at = excluded.created_at
            ",
            params![
                receipt.target_name,
                receipt.version,
                sequence,
                length,
                receipt.sha256.to_ascii_lowercase(),
                receipt.metadata_json,
                receipt.created_at,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn get_update_receipt(
        &self,
        target_name: &str,
    ) -> Result<Option<UpdateReceipt>, CoreError> {
        self.connection
            .lock()
            .query_row(
                "SELECT target_name, version, security_sequence, length, sha256, metadata_json,
                        created_at
                 FROM update_receipts WHERE target_name = ?1",
                [target_name],
                |row| {
                    let sequence = row.get::<_, i64>(2)?;
                    let length = row.get::<_, i64>(3)?;
                    Ok(UpdateReceipt {
                        target_name: row.get(0)?,
                        version: row.get(1)?,
                        security_sequence: sequence
                            .try_into()
                            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(2, sequence))?,
                        length: length
                            .try_into()
                            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, length))?,
                        sha256: row.get(4)?,
                        metadata_json: row.get(5)?,
                        created_at: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(CoreError::from)
    }

    pub fn record_update_journal(&self, journal: &UpdateJournalRecord) -> Result<(), CoreError> {
        if uuid::Uuid::parse_str(&journal.transaction_id).is_err()
            || !is_update_state(&journal.state)
            || serde_json::from_str::<serde_json::Value>(&journal.journal_json).is_err()
        {
            return Err(CoreError::SupplyChain(
                "update journal contains invalid transaction data".into(),
            ));
        }
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;
        let current = transaction
            .query_row(
                "SELECT state FROM update_journals WHERE transaction_id = ?1",
                [&journal.transaction_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if current
            .as_deref()
            .is_some_and(|state| !valid_update_transition(state, &journal.state))
        {
            return Err(CoreError::SupplyChain(
                "update journal state transition was rejected".into(),
            ));
        }
        transaction.execute(
            "
            INSERT INTO update_journals (transaction_id, state, journal_json, updated_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(transaction_id) DO UPDATE SET
                state = excluded.state,
                journal_json = excluded.journal_json,
                updated_at = excluded.updated_at
            ",
            params![
                journal.transaction_id,
                journal.state,
                journal.journal_json,
                journal.updated_at,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list_update_journals(&self) -> Result<Vec<UpdateJournalRecord>, CoreError> {
        let connection = self.connection.lock();
        let mut statement = connection.prepare(
            "SELECT transaction_id, state, journal_json, updated_at
             FROM update_journals ORDER BY datetime(updated_at) DESC, transaction_id DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(UpdateJournalRecord {
                transaction_id: row.get(0)?,
                state: row.get(1)?,
                journal_json: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CoreError::from)
    }

    pub fn trust_sftp_host_key(&self, record: &SftpHostKeyRecord) -> Result<(), CoreError> {
        self.connection.lock().execute(
            "
            INSERT INTO trusted_sftp_keys (
                host, port, algorithm, raw_key_base64, fingerprint_sha256,
                first_seen, last_verified, revoked
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(host, port, algorithm, raw_key_base64) DO UPDATE SET
                fingerprint_sha256 = excluded.fingerprint_sha256,
                last_verified = excluded.last_verified,
                revoked = excluded.revoked
            ",
            params![
                record.host,
                i64::from(record.port),
                record.algorithm,
                record.raw_key_base64,
                record.fingerprint_sha256,
                record.first_seen,
                record.last_verified,
                record.revoked,
            ],
        )?;
        Ok(())
    }

    pub fn replace_sftp_host_key(&self, record: &SftpHostKeyRecord) -> Result<(), CoreError> {
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;
        transaction.execute(
            "UPDATE trusted_sftp_keys SET revoked = 1 WHERE host = ?1 AND port = ?2",
            params![record.host, i64::from(record.port)],
        )?;
        transaction.execute(
            "
            INSERT INTO trusted_sftp_keys (
                host, port, algorithm, raw_key_base64, fingerprint_sha256,
                first_seen, last_verified, revoked
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)
            ON CONFLICT(host, port, algorithm, raw_key_base64) DO UPDATE SET
                fingerprint_sha256 = excluded.fingerprint_sha256,
                last_verified = excluded.last_verified,
                revoked = 0
            ",
            params![
                record.host,
                i64::from(record.port),
                record.algorithm,
                record.raw_key_base64,
                record.fingerprint_sha256,
                record.first_seen,
                record.last_verified,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn trusted_sftp_host_keys(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Vec<SftpHostKeyRecord>, CoreError> {
        let connection = self.connection.lock();
        let mut statement = connection.prepare(
            "
            SELECT host, port, algorithm, raw_key_base64, fingerprint_sha256,
                   first_seen, last_verified, revoked
            FROM trusted_sftp_keys
            WHERE host = ?1 AND port = ?2 AND revoked = 0
            ORDER BY algorithm, first_seen
            ",
        )?;
        let rows = statement.query_map(params![host, i64::from(port)], |row| {
            let port = row.get::<_, i64>(1)?;
            Ok(SftpHostKeyRecord {
                host: row.get(0)?,
                port: u16::try_from(port).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Integer,
                        Box::new(error),
                    )
                })?,
                algorithm: row.get(2)?,
                raw_key_base64: row.get(3)?,
                fingerprint_sha256: row.get(4)?,
                first_seen: row.get(5)?,
                last_verified: row.get(6)?,
                revoked: row.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CoreError::from)
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_update_state(value: &str) -> bool {
    matches!(
        value,
        "prepared"
            | "download_failed"
            | "downloaded"
            | "applying"
            | "waiting_for_exit"
            | "swapped"
            | "launched"
            | "healthy"
            | "committed"
            | "rolled_back"
            | "aborted"
            | "rollback_failed"
    )
}

fn valid_update_transition(current: &str, next: &str) -> bool {
    current == next
        || matches!(
            (current, next),
            ("prepared", "downloaded" | "download_failed")
                | ("download_failed", "downloaded")
                | ("downloaded", "applying")
                | (
                    "applying",
                    "waiting_for_exit"
                        | "swapped"
                        | "launched"
                        | "healthy"
                        | "committed"
                        | "rolled_back"
                        | "aborted"
                        | "rollback_failed"
                )
                | ("waiting_for_exit", "swapped" | "aborted")
                | (
                    "swapped",
                    "launched" | "healthy" | "rolled_back" | "rollback_failed"
                )
                | (
                    "launched",
                    "healthy" | "committed" | "rolled_back" | "rollback_failed"
                )
                | ("healthy", "committed" | "rolled_back" | "rollback_failed")
        )
}

#[cfg(test)]
mod tests {
    use crate::job::JobSpec;
    use crate::source::InputSource;

    use super::*;

    fn sample_job() -> JobSnapshot {
        JobSnapshot::new(JobSpec {
            source: InputSource::Url {
                value: "https://example.com/video".into(),
            },
            destination: "downloads".into(),
            preferred_kind: None,
            selected_format: None,
            subtitle_languages: Vec::new(),
            selected_playlist_entries: None,
            overwrite: false,
        })
    }

    #[test]
    fn persists_round_trip_without_credentials() {
        let store = JobStore::open_in_memory().unwrap();
        let job = sample_job();
        store.save(&job).unwrap();
        assert_eq!(store.get(job.id).unwrap(), Some(job));
    }

    #[test]
    fn interrupts_active_jobs_after_restart() {
        let store = JobStore::open_in_memory().unwrap();
        let mut job = sample_job();
        job.state = JobState::Downloading;
        store.save(&job).unwrap();
        assert_eq!(store.mark_active_jobs_interrupted().unwrap(), 1);
        assert_eq!(
            store.get(job.id).unwrap().unwrap().state,
            JobState::Interrupted
        );
    }

    #[test]
    fn refuses_pack_security_sequence_rollback() {
        let store = JobStore::open_in_memory().unwrap();
        store
            .advance_pack_security_high_water("video-core", 3)
            .unwrap();
        assert!(
            store
                .advance_pack_security_high_water("video-core", 2)
                .is_err()
        );
        assert_eq!(store.pack_security_high_water("video-core").unwrap(), 3);
    }

    #[test]
    fn persists_public_sftp_host_keys_without_credentials() {
        let store = JobStore::open_in_memory().unwrap();
        let record = SftpHostKeyRecord {
            host: "sftp.example.test".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            raw_key_base64: "a2V5".into(),
            fingerprint_sha256: "SHA256:example".into(),
            first_seen: "2026-08-09T00:00:00Z".into(),
            last_verified: "2026-08-09T00:00:00Z".into(),
            revoked: false,
        };
        store.trust_sftp_host_key(&record).unwrap();
        assert_eq!(
            store
                .trusted_sftp_host_keys(&record.host, record.port)
                .unwrap(),
            vec![record]
        );
    }

    #[test]
    fn replacing_an_sftp_host_key_revokes_the_previous_identity() {
        let store = JobStore::open_in_memory().unwrap();
        let previous = SftpHostKeyRecord {
            host: "sftp.example.test".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            raw_key_base64: "b2xk".into(),
            fingerprint_sha256: "11".repeat(32),
            first_seen: "2026-08-09T00:00:00Z".into(),
            last_verified: "2026-08-09T00:00:00Z".into(),
            revoked: false,
        };
        let replacement = SftpHostKeyRecord {
            raw_key_base64: "bmV3".into(),
            fingerprint_sha256: "22".repeat(32),
            last_verified: "2026-08-15T00:00:00Z".into(),
            ..previous.clone()
        };
        store.trust_sftp_host_key(&previous).unwrap();
        store.replace_sftp_host_key(&replacement).unwrap();
        assert_eq!(
            store
                .trusted_sftp_host_keys(&replacement.host, replacement.port)
                .unwrap(),
            vec![replacement]
        );
    }

    #[test]
    fn persists_pack_consent_without_secrets() {
        let store = JobStore::open_in_memory().unwrap();
        let consent = PackConsentRecord {
            pack_id: "video-core".into(),
            manifest_sha256: "11".repeat(32),
            license_digest: "22".repeat(32),
            accepted_size: 42,
            auto_update: true,
            accepted_at: "2026-08-09T00:00:00Z".into(),
            updated_at: "2026-08-09T00:00:00Z".into(),
        };
        store.save_pack_consent(&consent).unwrap();
        assert_eq!(store.pack_consent("video-core").unwrap(), Some(consent));
    }

    #[test]
    fn activation_commit_advances_high_water_atomically() {
        let store = JobStore::open_in_memory().unwrap();
        let pointer = crate::pack::ActivationPointer {
            pack_id: "video-core".into(),
            version: "1.0.0".into(),
            target: crate::engine::TargetId::current().unwrap(),
            security_sequence: 3,
            manifest_sha256: "33".repeat(32),
        };
        store.commit_pack_activation(&pointer).unwrap();
        assert_eq!(store.pack_security_high_water("video-core").unwrap(), 3);

        let mut rollback = pointer.clone();
        rollback.version = "0.9.0".into();
        rollback.security_sequence = 2;
        assert!(store.commit_pack_activation(&rollback).is_err());
        assert_eq!(store.pack_security_high_water("video-core").unwrap(), 3);
    }

    #[test]
    fn update_receipts_are_monotonic_and_exact_replays_are_idempotent() {
        let store = JobStore::open_in_memory().unwrap();
        let receipt = UpdateReceipt {
            target_name: "core/windows-x64.json".into(),
            version: "0.1.0-beta.2".into(),
            security_sequence: 2,
            length: 42,
            sha256: "44".repeat(32),
            metadata_json: r#"{"schema_version":1}"#.into(),
            created_at: "2026-08-14T00:00:00Z".into(),
        };
        store.save_update_receipt(&receipt).unwrap();
        store.save_update_receipt(&receipt).unwrap();
        assert_eq!(
            store.get_update_receipt(&receipt.target_name).unwrap(),
            Some(receipt.clone())
        );

        let mut replay = receipt.clone();
        replay.sha256 = "55".repeat(32);
        assert!(store.save_update_receipt(&replay).is_err());
        let mut rollback = receipt;
        rollback.security_sequence = 1;
        assert!(store.save_update_receipt(&rollback).is_err());
    }

    #[test]
    fn update_journals_round_trip_newest_first() {
        let store = JobStore::open_in_memory().unwrap();
        let first = UpdateJournalRecord {
            transaction_id: uuid::Uuid::new_v4().to_string(),
            state: "prepared".into(),
            journal_json: r#"{"state":"prepared"}"#.into(),
            updated_at: "2026-08-14T00:00:00Z".into(),
        };
        let second = UpdateJournalRecord {
            transaction_id: uuid::Uuid::new_v4().to_string(),
            state: "committed".into(),
            journal_json: r#"{"state":"committed"}"#.into(),
            updated_at: "2026-08-14T01:00:00Z".into(),
        };
        store.record_update_journal(&first).unwrap();
        store.record_update_journal(&second).unwrap();
        assert_eq!(store.list_update_journals().unwrap(), vec![second, first]);
    }

    #[test]
    fn update_journal_rejects_skipped_and_terminal_transitions() {
        let store = JobStore::open_in_memory().unwrap();
        let transaction_id = uuid::Uuid::new_v4().to_string();
        let record = |state: &str| UpdateJournalRecord {
            transaction_id: transaction_id.clone(),
            state: state.into(),
            journal_json: format!(r#"{{"state":"{state}"}}"#),
            updated_at: "2026-08-15T00:00:00Z".into(),
        };
        store.record_update_journal(&record("prepared")).unwrap();
        assert!(store.record_update_journal(&record("applying")).is_err());
        store.record_update_journal(&record("downloaded")).unwrap();
        store.record_update_journal(&record("applying")).unwrap();
        store.record_update_journal(&record("committed")).unwrap();
        assert!(store.record_update_journal(&record("rolled_back")).is_err());
    }
}
