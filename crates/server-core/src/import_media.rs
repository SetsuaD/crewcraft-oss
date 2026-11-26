//! Imported media (docs/IMPORT.md "Importing a bundle", files; task T350e): a captured file of an imported message is
//! stored in the file store exactly as an upload is (hashed, checked against the bundle's size and SHA-256, identical
//! bytes stored once) and attached to its message; a file the export did not capture is kept by name and size only, and
//! clients show it as "not archived". A later run stores newly captured files and never drops one already stored.
//!
//! Owns: `ImportedFile`, storing one captured file (`DurableServer::store_imported_file`), and the attachments of an
//! imported message (`DurableServer::imported_attachments`). Called by `import` (the engine) and by
//! `DurableServer::attachments`; calls `file_store` and `DurableServer::record_file`.

use std::fs::File;
use std::io::Read;

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::durable::{DurableError, DurableServer, FileError, MAX_FILE_SIZE, StoredFile, valid_file_name};
use crate::import::{ARCHIVE_OWNER, BundleFile};

/// The file id clients are sent for a file the export did not capture: no file has it, so it is never found.
pub const NOT_ARCHIVED: [u8; 16] = [0; 16];
/// How much of a file is read at a time while it is stored.
const CHUNK: usize = 256 * 1024;

/// One file of an imported message: stored (`id`) or not archived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedFile {
    pub name: String,
    pub size: u64,
    pub id: Option<[u8; 16]>,
}

impl DurableServer {
    /// Store the captured bytes of `file` for the archive room `slug`, as `ARCHIVE_OWNER`'s upload, and return its id.
    /// The inner `Err` is why it was not stored (the part is reported and the file stays "not archived"); the outer is
    /// a storage failure of the journal.
    pub(crate) fn store_imported_file(&mut self, slug: &str, file: &BundleFile) -> Result<Result<[u8; 16], &'static str>, DurableError> {
        let Some(path) = &file.source else { return Ok(Err("the export did not capture it")) };
        let Some(store) = self.file_store() else { return Ok(Err("this server keeps no files")) };
        if !valid_file_name(&file.name) {
            return Ok(Err("its name is not a file name"));
        }
        let Ok(mut source) = File::open(path) else { return Ok(Err("its bytes cannot be read")) };
        let Ok(size) = source.metadata().map(|meta| meta.len()) else { return Ok(Err("its bytes cannot be read")) };
        if size == 0 || size > MAX_FILE_SIZE {
            return Ok(Err("it is empty or larger than 100 MB"));
        }
        if file.size != 0 && file.size != size {
            return Ok(Err("its bytes are not the size the bundle gives"));
        }
        let mut upload = [0u8; 16];
        OsRng.fill_bytes(&mut upload);
        if store.start(&upload).is_err() {
            return Ok(Err("the file store cannot take it"));
        }
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; CHUNK];
        let mut offset = 0u64;
        loop {
            let read = match source.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(_) => {
                    store.discard(&upload);
                    return Ok(Err("its bytes cannot be read"));
                }
            };
            hasher.update(&buffer[..read]);
            if store.write(&upload, offset, &buffer[..read]).is_err() {
                store.discard(&upload);
                return Ok(Err("the file store cannot take it"));
            }
            offset += read as u64;
        }
        let sha256: [u8; 32] = hasher.finalize().into();
        if file.sha256.is_some_and(|declared| declared != sha256) {
            store.discard(&upload);
            return Ok(Err("its bytes do not match the bundle's sha256"));
        }
        if offset != size || store.finish(&upload, size, &sha256).is_err() {
            store.discard(&upload);
            return Ok(Err("the file store cannot take it"));
        }
        let image = store.image_size(&sha256);
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let stored = StoredFile { room: slug.to_owned(), uploader: ARCHIVE_OWNER.to_owned(), sha256, size, name: file.name.clone(), image };
        match self.record_file(id, stored) {
            Ok(()) => Ok(Ok(id)),
            Err(FileError::Durable(error)) => Err(error),
            Err(_) => Ok(Err("the file record was refused")),
        }
    }

    /// The files of the imported message at `cursor` in `slug`, as pushes carry them (at most `push::MAX_ATTACHMENTS`):
    /// stored files with their ids and image sizes, the rest with `NOT_ARCHIVED`. `None` when it is not an imported
    /// message with files; a deleted message has none.
    pub(crate) fn imported_attachments(&self, slug: &str, cursor: u64) -> Option<Vec<crewcraft_proto::push::AttachedFile>> {
        let files = self.imported_files(slug, cursor)?;
        Some(
            files
                .iter()
                .take(crewcraft_proto::push::MAX_ATTACHMENTS)
                .map(|file| {
                    let id = file.id.unwrap_or(NOT_ARCHIVED);
                    let image = file.id.and_then(|id| self.stored_image(&id));
                    crewcraft_proto::push::AttachedFile { file: id, name: file.name.clone(), size: file.size, image }
                })
                .collect(),
        )
    }
}

/// The files a later run should keep for a message: each bundle file in order, keeping an id an earlier run stored
/// (matched by position and name) and taking a new one from `store` when the bundle now captures it; files an earlier
/// run stored that the bundle no longer lists are kept at the end. Never drops a stored file.
pub(crate) fn merge_files(
    existing: &[ImportedFile],
    bundle: &[BundleFile],
    mut store: impl FnMut(usize, &BundleFile) -> Result<Option<[u8; 16]>, DurableError>,
) -> Result<Vec<ImportedFile>, DurableError> {
    let mut merged = Vec::with_capacity(bundle.len().max(existing.len()));
    for (index, file) in bundle.iter().enumerate() {
        let kept = existing.get(index).filter(|old| old.name == file.name).and_then(|old| old.id);
        let id = match kept {
            Some(id) => Some(id),
            None if file.captured => store(index, file)?,
            None => None,
        };
        let size = existing.get(index).filter(|old| old.name == file.name && old.id.is_some()).map_or(file.size, |old| old.size);
        merged.push(ImportedFile { name: file.name.clone(), size, id });
    }
    for old in existing.iter().skip(bundle.len()) {
        if old.id.is_some() {
            merged.push(old.clone());
        }
    }
    Ok(merged)
}
