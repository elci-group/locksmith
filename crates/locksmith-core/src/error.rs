//! Error types for Locksmith core.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// The owner does not hold a lease on the resource.
    NotHeld { resource: String, owner: String },
    /// The resource (or a related resource in the hierarchy) is held in an
    /// incompatible mode and the operation cannot proceed immediately.
    Conflict { resource: String, reason: String },
    /// The resource or queue entry does not exist.
    NotFound(String),
    /// The request was malformed.
    Invalid(String),
    /// The caller lacks the required capability.
    PermissionDenied(String),
    /// Persistence layer failure.
    Store(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotHeld { resource, owner } => {
                write!(f, "owner '{owner}' does not hold a lease on '{resource}'")
            }
            Error::Conflict { resource, reason } => {
                write!(f, "conflict on '{resource}': {reason}")
            }
            Error::NotFound(what) => write!(f, "not found: {what}"),
            Error::Invalid(what) => write!(f, "invalid request: {what}"),
            Error::PermissionDenied(what) => write!(f, "permission denied: {what}"),
            Error::Store(what) => write!(f, "store error: {what}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Store(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
