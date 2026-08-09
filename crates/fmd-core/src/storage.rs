use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::error::CoreError;
use crate::job::{JobId, JobSnapshot, JobState};

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
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "
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
            PRAGMA user_version = 2;
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
        let target = pointer.target.to_string();
        let sequence = i64::try_from(pointer.security_sequence).map_err(|_| {
            CoreError::SupplyChain("pack security sequence exceeds SQLite range".into())
        })?;
        self.connection.lock().execute(
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
}
