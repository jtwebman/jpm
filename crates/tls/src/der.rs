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

    /// The next value as `(tag, contents)`, or `None` when it is not valid DER.
    pub fn read(&mut self) -> Option<(u8, &'a [u8])> {
        todo!("{}", self.data.len())
    }

    /// The next value when its tag is `tag`, contents only.
    pub fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        let (t, v) = self.read()?;
        (t == tag).then_some(v)
    }
}
