/// no_std IO traits
use alloc::vec::Vec;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum IOError {
    EOF,
    Other(&'static str),
}

pub type IOResult<T> = Result<T, IOError>;

pub trait ReadAt {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> IOResult<usize>;
}

impl ReadAt for &[u8] {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> IOResult<usize> {
        let offset = offset as usize;
        let buflen = buf.len();
        if offset + buflen <= self.len() {
            // buffer is slammer
            buf.copy_from_slice(&self[offset..offset + buflen]);
            Ok(buflen)
        } else if offset < self.len() {
            // buffer is bigger than data, but still has some data
            let len = self.len() - offset;
            buf[..len].copy_from_slice(&self[offset..]);
            Ok(len)
        } else {
            Ok(0)
        }
    }
}

pub trait Write {
    fn write(&mut self, buf: &[u8]) -> IOResult<usize>;
}

/// Cursor is a wrapper around a ReadAt that allows seeking and reading
pub struct Cursor<R>
where
    R: ReadAt,
{
    reader: R,
    pos: u64,
}

impl<R> Cursor<R>
where
    R: ReadAt,
{
    pub fn new(reader: R) -> Self {
        Self { reader, pos: 0 }
    }

    pub fn seek(&mut self, pos: u64) {
        self.pos = pos;
    }

    pub fn read(&mut self, buf: &mut [u8]) -> IOResult<usize> {
        let len = self.reader.read_at(self.pos, buf)?;
        self.pos += len as u64;
        Ok(len)
    }

    pub fn read_into<'a>(&mut self, buf: &'a mut [u8]) -> IOResult<&'a [u8]> {
        let len = self.reader.read_at(self.pos, buf)?;
        self.pos += len as u64;
        Ok(&buf[..len])
    }

    pub fn offset(&self) -> u64 {
        self.pos
    }

    pub fn read_all(&mut self) -> IOResult<Vec<u8>> {
        let mut buf = Vec::new();
        loop {
            let mut tmp = [0u8; 1024];
            let len = self.read(&mut tmp)?;
            if len == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..len]);
        }
        Ok(buf)
    }
}

impl<'a, T> Cursor<&'a [T]>
where
    &'a [T]: ReadAt,
{
    pub fn remaining_data(&self) -> &'a [T] {
        &self.reader[self.pos as usize..]
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_cursor_read() {
        let data = b"0123456789";

        let mut cursor = super::Cursor::new(data.as_ref());
        let mut buf = [0u8; 5];

        assert_eq!(cursor.read(&mut buf), Ok(5), "read 5 bytes");
        assert_eq!(buf.as_ref(), b"01234", "read 5 bytes");

        assert_eq!(cursor.read(&mut buf[..3]), Ok(3), "read 3 bytes");
        assert_eq!(buf.as_ref(), b"56734", "read 3 bytes");

        assert_eq!(cursor.read(&mut buf), Ok(2), "read final 2 bytes");
        assert_eq!(buf[..2].as_ref(), b"89", "read final 2 bytes");

        cursor.seek(4);
        assert_eq!(cursor.read(&mut buf), Ok(5), "read 5 bytes");
        assert_eq!(buf.as_ref(), b"45678", "read 5 bytes");

        assert_eq!(cursor.read(&mut buf[..0]), Ok(0), "read 0 bytes");
        assert_eq!(buf.as_ref(), b"45678", "read 0 bytes");

        assert_eq!(cursor.read_into(&mut buf), Ok(b"9".as_ref()), "read 1 byte");
        assert_eq!(buf[..1].as_ref(), b"9", "read 1 byte");

        assert_eq!(cursor.read(&mut buf), Ok(0), "read EOF");
        assert_eq!(buf.as_ref(), b"95678", "read EOF");
    }

    #[test]
    fn test_cursor_readall() {
        let data = (0..128).map(|_| (0..255u8)).flatten().collect::<Vec<u8>>();

        let data_len = data.len();

        let data_copy = data.clone();

        let mut cursor = super::Cursor::new(data.as_ref());

        let read_first: [u8; 128] = cursor
            .read_into(&mut [0u8; 128])
            .unwrap()
            .try_into()
            .unwrap();

        let remaining = cursor.read_all().unwrap();

        assert_eq!(read_first.len(), 128);

        assert_eq!(read_first, data_copy[..128].as_ref());

        assert_eq!(remaining.len(), data_len - 128);

        assert_eq!(remaining, data_copy[128..].as_ref());
    }
}
