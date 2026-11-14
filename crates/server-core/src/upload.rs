//! Reassembles a file uploaded in fixed-size chunks that may arrive out of order or more than once. Task T107.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadError {
    /// `chunk_size` is 0, `total_len` is over the limit, or there would be more than `MAX_CHUNKS` chunks.
    BadParameters,
    /// A chunk index past the last chunk.
    OutOfRange,
    /// A chunk of the wrong length: every chunk is `chunk_size` bytes except the last, which holds the rest.
    BadSize,
    /// A chunk index received again with different bytes.
    Conflict,
    /// `finish` before every chunk arrived; carries the lowest missing index.
    Incomplete(u64),
}

/// The most chunks one upload may have. Checked before anything is allocated, so a tiny `chunk_size` cannot make
/// the server reserve memory in proportion to a client-chosen count.
pub const MAX_CHUNKS: u64 = 4096;

pub struct Assembler {
    total_len: u64,
    chunk_size: u64,
    num_chunks: u64,
    stored: Vec<Option<Vec<u8>>>,
}

impl Assembler {
    /// A file of `total_len` bytes in chunks of `chunk_size`, refused with `BadParameters` when `chunk_size` is 0,
    /// `total_len > max_len`, or the file would need more than [`MAX_CHUNKS`] chunks.
    pub fn new(total_len: u64, chunk_size: u64, max_len: u64) -> Result<Self, UploadError> {
        if chunk_size == 0 {
            return Err(UploadError::BadParameters);
        }
        if total_len > max_len {
            return Err(UploadError::BadParameters);
        }
        let num_chunks = total_len.div_ceil(chunk_size);
        if num_chunks > MAX_CHUNKS {
            return Err(UploadError::BadParameters);
        }
        Ok(Self { total_len, chunk_size, num_chunks, stored: vec![None; num_chunks as usize] })
    }

    /// How many chunks the file has (0 for an empty file).
    pub fn chunks(&self) -> u64 {
        self.num_chunks
    }

    /// Store a chunk and return how many distinct chunks are held. Checks, in order: `OutOfRange`, `BadSize`, then
    /// `Conflict`. The same index again with the same bytes is accepted and changes nothing.
    pub fn put(&mut self, index: u64, bytes: &[u8]) -> Result<u64, UploadError> {
        if index >= self.num_chunks {
            return Err(UploadError::OutOfRange);
        }
        let expected_len = if index + 1 == self.num_chunks { self.total_len - (self.num_chunks - 1) * self.chunk_size } else { self.chunk_size };
        if bytes.len() as u64 != expected_len {
            return Err(UploadError::BadSize);
        }
        if let Some(ref existing) = self.stored[index as usize] {
            if existing.as_slice() != bytes {
                return Err(UploadError::Conflict);
            }
        } else {
            self.stored[index as usize] = Some(bytes.to_vec());
        }
        let count = self.stored.iter().filter(|c| c.is_some()).count() as u64;
        Ok(count)
    }

    /// The whole file, once every chunk is held.
    pub fn finish(self) -> Result<Vec<u8>, UploadError> {
        for i in 0..self.num_chunks {
            if self.stored[i as usize].is_none() {
                return Err(UploadError::Incomplete(i));
            }
        }
        let mut result = Vec::with_capacity(self.total_len as usize);
        for data in self.stored.into_iter().flatten() {
            result.extend(data);
        }
        Ok(result)
    }
}
