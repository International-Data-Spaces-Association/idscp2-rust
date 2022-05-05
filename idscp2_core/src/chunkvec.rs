/*
This has been copied from https://github.com/ctz/rustls/blob/main/rustls/src/vecbuf.rs

I did not find sufficient alternative crates, possible candidates i looked at were:
 - arraydeque (no chunked access)
 - slicedeque (no chunked access, no fixed-size allocation)
 - std::VecDeque (no chunked access, no fixed-size allocation)
 - bytes (?)

 However, the ChunkVecBuffer also is no fixed-size allocation.
*/

use bytes::{Buf};
use std::cmp;
use std::collections::VecDeque;
use std::io;
use std::io::Read;
use std::ops::Deref;

/// This is a byte buffer that is built from a vector
/// of byte vectors.  This avoids extra copies when
/// appending a new byte vector, at the expense of
/// more complexity when reading out.
#[allow(dead_code)]
pub struct ChunkVecBuffer<T> {
    chunks: VecDeque<T>,
    limit: usize,
}

impl<T: Deref<Target = [u8]>> ChunkVecBuffer<T> {
    pub fn new() -> ChunkVecBuffer<T> {
        ChunkVecBuffer {
            chunks: VecDeque::new(),
            limit: 0,
        }
    }

    /// Sets the upper limit on how many bytes this
    /// object can store.
    ///
    /// Setting a lower limit than the currently stored
    /// data is not an error.
    ///
    /// A zero limit is interpreted as no limit.
    #[allow(dead_code)]
    pub fn set_limit(&mut self, new_limit: usize) {
        self.limit = new_limit;
    }

    /// If we're empty
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// How many bytes we're storing
    pub fn len(&self) -> usize {
        let mut len = 0;
        for ch in &self.chunks {
            len += ch.len();
        }
        len
    }

    /// For a proposed append of `len` bytes, how many
    /// bytes should we actually append to adhere to the
    /// currently set `limit`?
    #[allow(dead_code)]
    pub fn apply_limit(&self, len: usize) -> usize {
        if self.limit == 0 {
            len
        } else {
            let space = self.limit.saturating_sub(self.len());
            cmp::min(len, space)
        }
    }

    /// Take one of the chunks from this object.  This
    /// function panics if the object `is_empty`.
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        self.chunks.pop_front()
    }
}

impl ChunkVecBuffer<Vec<u8>> {
    /// Append a copy of `bytes`, perhaps a prefix if
    /// we're near the limit.
    #[allow(dead_code)]
    pub fn append_limited_copy(&mut self, bytes: &[u8]) -> usize {
        let take = self.apply_limit(bytes.len());
        self.append(bytes[..take].to_vec());
        take
    }

    /// Read data out of this object, writing it into `buf`
    /// and returning how many bytes were written there.
    #[allow(dead_code)]
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut offs = 0;

        while offs < buf.len() && !self.is_empty() {
            let used = self.chunks[0].as_slice().read(&mut buf[offs..])?;

            self.consume(used);
            offs += used;
        }

        Ok(offs)
    }

    fn consume(&mut self, mut used: usize) {
        while let Some(mut buf) = self.pop() {
            if used < buf.len() {
                self.insert_front(buf.split_off(used));
                break;
            } else {
                used -= buf.len();
            }
        }
    }

    /// Read data out of this object, passing it `wr`
    #[allow(dead_code)]
    pub fn write_to(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }

        let mut bufs = [io::IoSlice::new(&[]); 64];
        for (iov, chunk) in bufs.iter_mut().zip(self.chunks.iter()) {
            *iov = io::IoSlice::new(chunk);
        }
        let len = cmp::min(bufs.len(), self.chunks.len());
        let used = wr.write_vectored(&bufs[..len])?;
        self.consume(used);
        Ok(used)
    }
}

impl<T: Deref<Target = [u8]>> ChunkVecBuffer<T> {
    /// Take and append the given `bytes`.
    pub fn append(&mut self, bytes: T) -> usize {
        let len = bytes.len();

        if !bytes.is_empty() {
            self.chunks.push_back(bytes);
        }

        len
    }

    /// Take and insert the given `bytes` at the start of the queue.
    pub fn insert_front(&mut self, bytes: T) -> usize {
        let len = bytes.len();

        if !bytes.is_empty() {
            self.chunks.push_back(bytes);
        }

        len
    }
}

impl<T: Deref<Target = [u8]> + Buf> Buf for ChunkVecBuffer<T> {
    fn remaining(&self) -> usize {
        self.len()
    }

    fn chunk(&self) -> &[u8] {
        self.chunks
            .front()
            .map(|x| x.deref())
            .unwrap_or_else(|| [0u8; 0].as_slice())
    }

    fn advance(&mut self, mut cnt: usize) {
        while cnt > 0 {
            let len = self.chunks.front().unwrap().len();
            if len < cnt {
                self.chunks.pop_front();
                cnt -= len;
            } else {
                let front = self.chunks.front_mut().unwrap();
                front.advance(cnt);
                break;
            }
        }
    }
}

impl<T: Deref<Target = [u8]>> Default for ChunkVecBuffer<T> {
    fn default() -> Self {
        ChunkVecBuffer::new()
    }
}

#[cfg(test)]
mod test {
    use super::ChunkVecBuffer;

    #[test]
    fn short_append_copy_with_limit() {
        let mut cvb = ChunkVecBuffer::new();
        cvb.set_limit(12);
        assert_eq!(cvb.append_limited_copy(b"hello"), 5);
        assert_eq!(cvb.append_limited_copy(b"world"), 5);
        assert_eq!(cvb.append_limited_copy(b"hello"), 2);
        assert_eq!(cvb.append_limited_copy(b"world"), 0);

        let mut buf = [0u8; 12];
        assert_eq!(cvb.read(&mut buf).unwrap(), 12);
        assert_eq!(buf.to_vec(), b"helloworldhe".to_vec());
    }
}
