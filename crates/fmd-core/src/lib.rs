//! Product-domain core shared by the desktop shell and future command-line clients.

pub mod adapter;
pub mod engine;
pub mod error;
pub mod executor;
pub mod job;
pub mod metalink;
pub mod pack;
pub mod process;
pub mod routing;
pub mod scheduler;
pub mod source;
pub mod storage;

pub use engine::{
    AdapterId, EngineCapability, EngineDescriptor, PackDependency, PackDescriptor, PackFile,
    PackFileRole, PackManifestV1, PackSelfTest, TargetId, UpstreamComponent,
};
pub use error::{ApiError, CoreError, EngineErrorKind};
pub use executor::JobExecutor;
pub use job::{
    FormatOption, JobEvent, JobId, JobSnapshot, JobSpec, JobState, PlaylistEntry, ResolvedPlan,
};
pub use metalink::{MetalinkFile, MetalinkLimits, MetalinkPreview};
pub use pack::{
    ActivationPointer, ArtifactDescriptorV1, AuthorizedDescriptorTarget, AuthorizedExternalTarget,
    DownloadedTarget, ExtractionLimits, PackInstaller, PackLayout, TufRepository,
};
pub use process::{
    ChildStdin, EngineCommand, ExpertArgsPolicy, OutputStream, ProcessLine, ProcessOutcome,
    ProcessSpec, ProcessSupervisor,
};
pub use routing::{RouteDecision, Router};
pub use scheduler::JobScheduler;
pub use source::{InputSource, SourceKind};
pub use storage::{
    JobStore, PackConsentRecord, SftpHostKeyRecord, UpdateJournalRecord, UpdateReceipt,
};

/// IPC adapter version required by engine descriptors shipped for this core.
pub const ADAPTER_API_VERSION: u32 = 1;
pub use adapter::{
    BuiltinCliAdapter, DownloadContext, DownloadOutcome, EngineAdapter, EngineFailure, EventSink,
    InstalledEngine, ProbeContext, TransferAuth,
};
