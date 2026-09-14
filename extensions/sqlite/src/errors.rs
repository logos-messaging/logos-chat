use libchat::StorageError;
use rusqlite::Error as RusqliteError;

pub(crate) fn map_rusqlite_error(err: RusqliteError) -> StorageError {
    StorageError::Database(err.to_string())
}

pub(crate) fn map_optional_row<T>(
    result: Result<T, RusqliteError>,
) -> Result<Option<T>, StorageError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
        Err(err) => Err(map_rusqlite_error(err)),
    }
}
