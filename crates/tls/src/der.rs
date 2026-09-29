//! A strict DER reader: definite, minimal lengths only, and nothing past a value's end. It
//! reads what X.509 needs and refuses the rest.

/// A tag-length-value reader over one level of a DER encoding.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// What is left to read.
    pub fn rest(&self) -> &'a [u8] {
        self.data
    }

    /// The next tag, without reading it.
    pub fn peek(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// The next value as `(tag, contents)`, or `None` when it is not valid DER. The reader
    /// does not move on `None`.
    ///
    /// Tags must fit in one byte (no high tag numbers). Lengths must be definite and minimal:
    /// the short form below 128, else the fewest length bytes (at most 4) with no leading
    /// zero. X.690 section 10.1.
    pub fn read(&mut self) -> Option<(u8, &'a [u8])> {
        let [tag, first, rest @ ..] = self.data else { return None };
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (len, rest) = match first {
            0..=0x7f => (*first as usize, rest),
            0x81..=0x84 => {
                let (bytes, rest) = rest.split_at_checked((first & 0x7f) as usize)?;
                let len = bytes.iter().fold(0, |acc, &b| acc << 8 | b as usize);
                if bytes[0] == 0 || len < 0x80 {
                    return None;
                }
                (len, rest)
            }
            _ => return None,
        };
        let (value, rest) = rest.split_at_checked(len)?;
        self.data = rest;
        Some((*tag, value))
    }

    /// The next value when its tag is `tag`, contents only.
    pub fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        let (t, v) = self.read()?;
        (t == tag).then_some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;

    fn one(der: &[u8]) -> Option<(u8, Vec<u8>)> {
        let mut r = Reader::new(der);
        let (t, v) = r.read()?;
        r.is_empty().then(|| (t, v.to_vec()))
    }

    #[test]
    fn short_form() {
        assert_eq!(one(&[0x04, 0]), Some((4, vec![])));
        assert_eq!(one(&[0x02, 1, 5]), Some((2, vec![5])));
        let mut v = vec![0x04, 0x7f];
        v.extend([7; 0x7f]);
        assert_eq!(one(&v), Some((4, vec![7; 0x7f])));
    }

    #[test]
    fn long_form_minimal() {
        for len in [0x80usize, 0xff, 0x100, 0xffff, 0x10000, 0x12345] {
            let mut v = vec![0x04];
            let bytes = len.to_be_bytes();
            let skip = bytes.iter().take_while(|&&b| b == 0).count();
            v.push(0x80 | (bytes.len() - skip) as u8);
            v.extend(&bytes[skip..]);
            v.extend(vec![1; len]);
            assert_eq!(one(&v).map(|(_, c)| c.len()), Some(len), "{len}");
        }
    }

    #[test]
    fn four_length_bytes() {
        // A 4-byte length is read; the data is short, so the value is refused but the form
        // itself is not.
        assert!(one(&[0x04, 0x84, 1, 0, 0, 0]).is_none());
        let mut r = Reader::new(&[0x04, 0x84, 0, 0, 0, 0x80]);
        assert!(r.read().is_none());
    }

    #[test]
    fn non_minimal_lengths() {
        // 0x81 for a length under 128.
        assert!(one(&[0x04, 0x81, 0x00]).is_none());
        assert!(one(&[0x04, 0x81, 0x01, 0]).is_none());
        assert!(one(&[0x04, 0x81, 0x7f]).is_none());
        // Leading zero length bytes.
        let mut v = vec![0x04, 0x82, 0x00, 0x80];
        v.extend([0; 0x80]);
        assert!(one(&v).is_none());
        let mut v = vec![0x04, 0x82, 0x00, 0xff];
        v.extend([0; 0xff]);
        assert!(one(&v).is_none());
        let mut v = vec![0x04, 0x83, 0x00, 0x01, 0x00];
        v.extend([0; 0x100]);
        assert!(one(&v).is_none());
        assert!(one(&[0x04, 0x84, 0, 0, 0, 1, 0]).is_none());
        assert!(one(&[0x04, 0x82, 0, 0]).is_none());
    }

    #[test]
    fn indefinite_and_long_lengths() {
        assert!(one(&[0x30, 0x80, 0, 0]).is_none());
        assert!(one(&[0x04, 0x85, 0, 0, 0, 0, 1, 0]).is_none());
        assert!(one(&[0x04, 0x88, 0, 0, 0, 0, 0, 0, 0, 1, 0]).is_none());
        assert!(one(&[0x04, 0xff]).is_none());
    }

    #[test]
    fn high_tag_numbers() {
        for tag in [0x1f, 0x3f, 0x5f, 0x7f, 0x9f, 0xbf, 0xdf, 0xff] {
            assert!(one(&[tag, 0x01, 0x01, 0]).is_none(), "{tag:x}");
            assert!(one(&[tag, 0]).is_none(), "{tag:x}");
        }
        for tag in [0x1e, 0x30, 0xa0, 0xa3, 0x82, 0x87] {
            assert_eq!(one(&[tag, 0]), Some((tag, vec![])));
        }
    }

    #[test]
    fn truncated() {
        assert!(one(&[]).is_none());
        assert!(one(&[0x04]).is_none());
        assert!(one(&[0x04, 1]).is_none());
        assert!(one(&[0x04, 3, 1, 2]).is_none());
        assert!(one(&[0x04, 0x81]).is_none());
        assert!(one(&[0x04, 0x82, 1]).is_none());
        assert!(one(&[0x04, 0x81, 0x80]).is_none());
        let mut v = vec![0x04, 0x82, 0x01, 0x00];
        v.extend([0; 0xff]);
        assert!(one(&v).is_none());
    }

    #[test]
    fn failure_does_not_move() {
        let data = [0x04, 0x81, 0x05, 0, 0, 0, 0, 0];
        let mut r = Reader::new(&data);
        assert!(r.read().is_none());
        assert_eq!(r.rest(), &data);
    }

    #[test]
    fn sequence_of_values() {
        let data = [0x02, 1, 1, 0x04, 0, 0x30, 3, 0x05, 0x01, 0x00];
        let mut r = Reader::new(&data);
        assert_eq!(r.peek(), Some(2));
        assert_eq!(r.expect(2), Some(&[1][..]));
        assert_eq!(r.expect(4), Some(&[][..]));
        // A wrong tag is `None` but still consumes the value.
        assert_eq!(r.expect(0x31), None);
        assert!(r.is_empty());
        assert_eq!(r.peek(), None);
        assert_eq!(r.read(), None);
    }

    #[test]
    fn exhaustive_two_and_three_byte_inputs() {
        // Every 2- and 3-byte input: accepted exactly when it is one short-form value that
        // fits, with a low tag number.
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let ok = a & 0x1f != 0x1f && b == 0;
                assert_eq!(one(&[a, b]).is_some(), ok, "{a:x} {b:x}");
                let ok = a & 0x1f != 0x1f && b == 1;
                assert_eq!(one(&[a, b, 0]).is_some(), ok, "{a:x} {b:x} 0");
            }
        }
    }
}
