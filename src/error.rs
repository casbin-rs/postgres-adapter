use deadpool_postgres::{BuildError, PoolError};
use std::{error::Error as StdError, fmt};
use tokio_postgres::Error as PostgresError;

#[derive(Debug)]
pub enum Error {
    PostgresError(PostgresError),
    PoolError(PoolError),
    BuildError(BuildError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;

        match self {
            PostgresError(pg_err) => pg_err.fmt(f),
            PoolError(pg_err) => pg_err.fmt(f),
            BuildError(pg_err) => pg_err.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        use Error::*;

        match self {
            PostgresError(pg_err) => Some(pg_err),
            PoolError(pg_err) => Some(pg_err),
            BuildError(pg_err) => Some(pg_err),
        }
    }
}

impl From<PostgresError> for Error {
    fn from(pg_err: PostgresError) -> Self {
        Error::PostgresError(pg_err)
    }
}

impl From<PoolError> for Error {
    fn from(pg_err: PoolError) -> Self {
        Error::PoolError(pg_err)
    }
}
impl From<BuildError> for Error {
    fn from(pg_err: BuildError) -> Self {
        Error::BuildError(pg_err)
    }
}
