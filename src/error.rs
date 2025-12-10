//! Shared application errors and exit codes.
use anyhow::Error;

#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
#[repr(i32)]
/// Stable process exit codes surfaced to users (and JSON consumers).
pub enum ExitCode {
    Ok = 0,
    UserError = 1,
    NotAuthenticated = 2,
    NetworkError = 3,
    TargetRejected = 4,
    VaultError = 5,
    GitError = 6,
}

#[derive(Debug)]
/// Error wrapper carrying both an exit code and the underlying error.
pub struct AppError {
    pub code: ExitCode,
    pub error: Error,
}

impl AppError {
    pub fn new(code: ExitCode, error: Error) -> Self {
        Self { code, error }
    }
    pub fn user(error: Error) -> Self {
        Self::new(ExitCode::UserError, error)
    }
    pub fn auth(error: Error) -> Self {
        Self::new(ExitCode::NotAuthenticated, error)
    }
    pub fn git(error: Error) -> Self {
        Self::new(ExitCode::GitError, error)
    }
}

impl From<anyhow::Error> for AppError {
    fn from(error: Error) -> Self {
        AppError::user(error)
    }
}

impl From<RepoBindingError> for AppError {
    fn from(err: RepoBindingError) -> Self {
        match err.kind {
            RepoBindingErrorKind::User => AppError::user(err.error),
            RepoBindingErrorKind::Git => AppError::git(err.error),
        }
    }
}


#[derive(Debug, Clone, Copy)]
pub enum RepoBindingErrorKind {
    User,
    Git,
}

#[derive(Debug)]
pub struct RepoBindingError {
    pub kind: RepoBindingErrorKind,
    pub error: anyhow::Error,
}

impl std::fmt::Display for RepoBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for RepoBindingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}



