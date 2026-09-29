//! JSON: a strict parser into an order-keeping `Value`, a lazy scanner that skips what it is not
//! asked for, and output that matches JavaScript's `JSON.stringify`.
//!
//! The scanner is what reads registry documents: a packument can be megabytes, of which a pick
//! reads a few fields. Strings are found eight bytes at a time (SWAR: bit tricks on a `u64`,
//! the same on every CPU, no per-architecture code), and a skipped value is never copied.

use std::borrow::Cow;
use std::fmt::Write as _;

use crate::error::{Error, Result};

/// How deep arrays and objects may nest before the document is refused, not the stack.
const MAX_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Default)]
pub enum Value {
    #[default]
    Null,
    Bool(bool),
    /// The number as written, checked against JSON's grammar.
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(Object),
}

/// An object's members in document order, as JavaScript keeps them. A key given twice keeps
/// its first place and its last value, as `JSON.parse` does.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Object(Vec<(String, Value)>);

impl Object {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.0.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Set a member: in place when the key is there, at the end otherwise.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) {
        let key = key.into();
        match self.get_mut(&key) {
            Some(v) => *v = value,
            None => self.0.push((key, value)),
        }
    }

    /// Remove a member, keeping the others in order.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let at = self.0.iter().position(|(k, _)| k == key)?;
        Some(self.0.remove(at).1)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.0.iter().map(|(k, v)| (k, v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.iter().map(|(k, _)| k)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A lookup table for a big object, where `get` would scan.
    pub fn index(&self) -> std::collections::HashMap<&str, &Value> {
        self.0.iter().map(|(k, v)| (k.as_str(), v)).collect()
    }

    pub fn sort_keys(&mut self) {
        self.0.sort_by(|a, b| a.0.cmp(&b.0));
    }
}

impl<'a> IntoIterator for &'a Object {
    type Item = (&'a String, &'a Value);
    type IntoIter =
        std::iter::Map<std::slice::Iter<'a, (String, Value)>, fn(&'a (String, Value)) -> (&'a String, &'a Value)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter().map(|(k, v)| (k, v))
    }
}

impl FromIterator<(String, Value)> for Object {
    fn from_iter<I: IntoIterator<Item = (String, Value)>>(iter: I) -> Self {
        let mut o = Self::new();
        for (k, v) in iter {
            o.insert(k, v);
        }
        o
    }
}

impl std::fmt::Display for Value {
    /// Compact JSON, as `JSON.stringify` writes it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&to_string(self))
    }
}

impl Value {
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// The same value whatever order its objects' members are in: for comparing two documents
    /// as maps, the way JavaScript code compares them key by key.
    pub fn same_as(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Object(a), Self::Object(b)) => {
                a.len() == b.len() && a.iter().all(|(k, v)| b.get(k).is_some_and(|w| v.same_as(w)))
            }
            (Self::Array(a), Self::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.same_as(y)),
            _ => self == other,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    /// A member of an object; `None` for a missing key or a value that is not an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object()?.get(key)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&String> for Value {
    fn from(s: &String) -> Self {
        Self::String(s.clone())
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Self::Number(n.to_string())
    }
}

impl From<usize> for Value {
    fn from(n: usize) -> Self {
        Self::Number(n.to_string())
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Self::Number(n.to_string())
    }
}

impl From<Object> for Value {
    fn from(o: Object) -> Self {
        Self::Object(o)
    }
}

impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Self::Array(v.into_iter().map(Into::into).collect())
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        v.map_or(Self::Null, Into::into)
    }
}

/// An object from `(key, value)` pairs: `obj([("a", 1u64.into())])`.
pub fn obj<const N: usize>(members: [(&str, Value); N]) -> Value {
    Value::Object(members.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// An object whose every value is a string, as a map; `None` for anything else.
pub fn string_map(v: &Value) -> Option<std::collections::BTreeMap<String, String>> {
    v.as_object()?.iter().map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect()
}

/// A map of strings as an object, in the map's order.
pub fn str_map<'a>(map: impl IntoIterator<Item = (&'a String, &'a String)>) -> Value {
    Value::Object(map.into_iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect())
}

// --- parsing ----------------------------------------------------------------------------------

/// Strict parse of a whole document, as `JSON.parse` reads it.
pub fn parse(text: &str) -> Result<Value> {
    let mut s = Scan::new(text);
    let v = s.value()?;
    s.ws();
    if s.pos < s.src.len() {
        return Err(s.fail("unexpected text after the document"));
    }
    Ok(v)
}

/// A cursor over a document. The caller walks objects member by member and either reads a
/// value (`value`, `string`) or passes over it (`skip`, `span`).
pub struct Scan<'a> {
    text: &'a str,
    src: &'a [u8],
    pub pos: usize,
    depth: usize,
}

const ONES: u64 = 0x0101_0101_0101_0101;
const HIGH: u64 = 0x8080_8080_8080_8080;

/// High bit set in each byte of `w` that equals `c`.
#[inline]
fn eq_byte(w: u64, c: u8) -> u64 {
    let x = w ^ (ONES * u64::from(c));
    !(((x & !HIGH) + !HIGH) | x | !HIGH)
}

/// High bit set in each byte that is a quote, a backslash or a control character: every byte a
/// string scan has to stop at. Exact, so the lowest set bit is the first such byte.
#[inline]
fn string_stop(w: u64) -> u64 {
    let control = w.wrapping_sub(ONES * 0x20) & !w & HIGH;
    control | eq_byte(w, b'"') | eq_byte(w, b'\\')
}

impl<'a> Scan<'a> {
    pub fn new(text: &'a str) -> Self {
        Self { text, src: text.as_bytes(), pos: 0, depth: 0 }
    }

    fn fail(&self, what: &str) -> Error {
        Error::new("EJSONPARSE", format!("{what} at position {}", self.pos))
    }

    #[inline]
    pub fn ws(&mut self) {
        while let Some(b' ' | b'\n' | b'\r' | b'\t') = self.src.get(self.pos) {
            self.pos += 1;
        }
    }

    #[inline]
    fn peek(&mut self) -> Option<u8> {
        self.ws();
        self.src.get(self.pos).copied()
    }

    fn expect(&mut self, c: u8) -> Result<()> {
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.fail(&format!("expected '{}'", c as char)))
        }
    }

    /// The first byte at or after `from` that a string scan stops at.
    #[inline]
    fn string_end(&self, mut at: usize) -> usize {
        while at + 8 <= self.src.len() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&self.src[at..at + 8]);
            let hit = string_stop(u64::from_le_bytes(w));
            if hit != 0 {
                return at + (hit.trailing_zeros() / 8) as usize;
            }
            at += 8;
        }
        while at < self.src.len() && !matches!(self.src[at], b'"' | b'\\' | 0..=0x1f) {
            at += 1;
        }
        at
    }

    /// A string at the cursor, borrowed when it holds no escape.
    pub fn string(&mut self) -> Result<Cow<'a, str>> {
        self.expect(b'"')?;
        let start = self.pos;
        let end = self.string_end(start);
        match self.src.get(end) {
            Some(b'"') => {
                self.pos = end + 1;
                Ok(Cow::Borrowed(&self.text[start..end]))
            }
            Some(b'\\') => self.unescape(start, end).map(Cow::Owned),
            Some(_) => {
                self.pos = end;
                Err(self.fail("control character in a string"))
            }
            None => Err(self.fail("unterminated string")),
        }
    }

    fn unescape(&mut self, start: usize, first: usize) -> Result<String> {
        let mut out = String::with_capacity(first - start + 16);
        out.push_str(&self.text[start..first]);
        self.pos = first;
        loop {
            match self.src.get(self.pos) {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    let c = *self.src.get(self.pos + 1).ok_or_else(|| self.fail("unterminated string"))?;
                    self.pos += 2;
                    match c {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&hi) && self.src[self.pos..].starts_with(b"\\u") {
                                self.pos += 2;
                                let lo = self.hex4()?;
                                if (0xDC00..0xE000).contains(&lo) {
                                    char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
                                } else {
                                    // A lone high surrogate, then another escape: both stand alone.
                                    out.push('\u{FFFD}');
                                    char::from_u32(lo)
                                }
                            } else {
                                char::from_u32(hi)
                            };
                            // A lone surrogate cannot be a Rust `char`; it reads as U+FFFD.
                            out.push(ch.unwrap_or('\u{FFFD}'));
                        }
                        _ => return Err(self.fail("invalid escape")),
                    }
                }
                Some(0..=0x1f) => return Err(self.fail("control character in a string")),
                Some(_) => {
                    let end = self.string_end(self.pos);
                    out.push_str(&self.text[self.pos..end]);
                    self.pos = end;
                    if end >= self.src.len() {
                        return Err(self.fail("unterminated string"));
                    }
                }
                None => return Err(self.fail("unterminated string")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32> {
        let digits = self.src.get(self.pos..self.pos + 4).ok_or_else(|| self.fail("short \\u escape"))?;
        let s = std::str::from_utf8(digits).map_err(|_| self.fail("bad \\u escape"))?;
        let v = u32::from_str_radix(s, 16).map_err(|_| self.fail("bad \\u escape"))?;
        self.pos += 4;
        Ok(v)
    }

    fn number(&mut self) -> Result<&'a str> {
        let start = self.pos;
        let digits = |s: &mut Self| {
            let from = s.pos;
            while s.src.get(s.pos).is_some_and(u8::is_ascii_digit) {
                s.pos += 1;
            }
            s.pos > from
        };
        if self.src.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        match self.src.get(self.pos) {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                digits(self);
            }
            _ => return Err(self.fail("invalid number")),
        }
        if self.src.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            if !digits(self) {
                return Err(self.fail("invalid number"));
            }
        }
        if let Some(b'e' | b'E') = self.src.get(self.pos) {
            self.pos += 1;
            if let Some(b'+' | b'-') = self.src.get(self.pos) {
                self.pos += 1;
            }
            if !digits(self) {
                return Err(self.fail("invalid number"));
            }
        }
        Ok(&self.text[start..self.pos])
    }

    fn literal(&mut self, word: &[u8]) -> Result<()> {
        if self.src[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(())
        } else {
            Err(self.fail("unexpected token"))
        }
    }

    fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.fail("nested too deeply"));
        }
        Ok(())
    }

    /// The value at the cursor, parsed in full.
    pub fn value(&mut self) -> Result<Value> {
        match self.peek() {
            Some(b'"') => Ok(Value::String(self.string()?.into_owned())),
            Some(b'{') => {
                self.enter()?;
                let mut members: Vec<(String, Value)> = Vec::new();
                let mut seen: Option<std::collections::HashMap<String, usize>> = None;
                self.members(|s, key| {
                    let value = s.value()?;
                    // A big object keeps an index, so a repeated key stays linear to find.
                    if members.len() == 16 && seen.is_none() {
                        seen = Some(members.iter().enumerate().map(|(i, (k, _))| (k.clone(), i)).collect());
                    }
                    let at = match &seen {
                        Some(index) => index.get(key.as_ref()).copied(),
                        None => members.iter().position(|(k, _)| k == key.as_ref()),
                    };
                    match at {
                        Some(i) => members[i].1 = value,
                        None => {
                            if let Some(index) = &mut seen {
                                index.insert(key.to_string(), members.len());
                            }
                            members.push((key.into_owned(), value));
                        }
                    }
                    Ok(())
                })?;
                self.depth -= 1;
                Ok(Value::Object(Object(members)))
            }
            Some(b'[') => {
                self.enter()?;
                self.pos += 1;
                let mut items = Vec::new();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                } else {
                    loop {
                        items.push(self.value()?);
                        match self.peek() {
                            Some(b',') => self.pos += 1,
                            Some(b']') => {
                                self.pos += 1;
                                break;
                            }
                            _ => return Err(self.fail("expected ',' or ']'")),
                        }
                    }
                }
                self.depth -= 1;
                Ok(Value::Array(items))
            }
            Some(b't') => self.literal(b"true").map(|()| Value::Bool(true)),
            Some(b'f') => self.literal(b"false").map(|()| Value::Bool(false)),
            Some(b'n') => self.literal(b"null").map(|()| Value::Null),
            Some(_) => Ok(Value::Number(self.number()?.to_string())),
            None => Err(self.fail("unexpected end of document")),
        }
    }

    /// Each member of the object at the cursor: `each` gets its key and must read or skip its
    /// value.
    pub fn members(&mut self, mut each: impl FnMut(&mut Self, Cow<'a, str>) -> Result<()>) -> Result<()> {
        self.expect(b'{')?;
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            let key = self.string()?;
            self.expect(b':')?;
            each(self, key)?;
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return Err(self.fail("expected ',' or '}'")),
            }
        }
    }

    /// Whether the value at the cursor is an object.
    pub fn at_object(&mut self) -> bool {
        self.peek() == Some(b'{')
    }

    /// Whether the value at the cursor is a string.
    pub fn at_string(&mut self) -> bool {
        self.peek() == Some(b'"')
    }

    /// Pass over the value at the cursor without building it. Strings are jumped over eight
    /// bytes at a time; brackets are counted, and nothing is copied. Structure is checked
    /// (every string ends, brackets balance), numbers and literals only by their first byte.
    pub fn skip(&mut self) -> Result<()> {
        match self.peek() {
            Some(b'"') => {
                self.pos += 1;
                self.skip_string_body()
            }
            Some(b'{' | b'[') => {
                let mut depth = 0usize;
                loop {
                    match self.src.get(self.pos) {
                        Some(b'{' | b'[') => {
                            depth += 1;
                            if depth > MAX_DEPTH {
                                return Err(self.fail("nested too deeply"));
                            }
                            self.pos += 1;
                        }
                        Some(b'}' | b']') => {
                            self.pos += 1;
                            depth -= 1;
                            if depth == 0 {
                                return Ok(());
                            }
                        }
                        Some(b'"') => {
                            self.pos += 1;
                            self.skip_string_body()?;
                        }
                        Some(_) => self.pos += 1,
                        None => return Err(self.fail("unterminated value")),
                    }
                }
            }
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(_) => self.number().map(|_| ()),
            None => Err(self.fail("unexpected end of document")),
        }
    }

    fn skip_string_body(&mut self) -> Result<()> {
        loop {
            let end = self.string_end(self.pos);
            match self.src.get(end) {
                Some(b'"') => {
                    self.pos = end + 1;
                    return Ok(());
                }
                Some(b'\\') => self.pos = end + 2,
                Some(_) => {
                    self.pos = end;
                    return Err(self.fail("control character in a string"));
                }
                None => return Err(self.fail("unterminated string")),
            }
        }
    }

    /// Skip the value at the cursor, and give back where it was: to parse later, or never.
    pub fn span(&mut self) -> Result<(usize, usize)> {
        self.ws();
        let start = self.pos;
        self.skip()?;
        Ok((start, self.pos))
    }
}

// --- writing ----------------------------------------------------------------------------------

/// `JSON.stringify(value)`.
pub fn to_string(v: &Value) -> String {
    let mut out = String::new();
    write(&mut out, v, None, 0);
    out
}

/// `JSON.stringify(value, null, indent)`, with a newline at the end as files are written.
pub fn to_pretty(v: &Value, indent: &str) -> String {
    let mut out = String::new();
    write(&mut out, v, Some(indent), 0);
    out.push('\n');
    out
}

fn newline(out: &mut String, indent: Option<&str>, depth: usize) {
    if let Some(i) = indent {
        out.push('\n');
        for _ in 0..depth {
            out.push_str(i);
        }
    }
}

fn write(out: &mut String, v: &Value, indent: Option<&str>, depth: usize) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&js_number(n)),
        Value::String(s) => quote(out, s),
        Value::Array(items) if items.is_empty() => out.push_str("[]"),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, indent, depth + 1);
                write(out, item, indent, depth + 1);
            }
            newline(out, indent, depth);
            out.push(']');
        }
        Value::Object(o) if o.is_empty() => out.push_str("{}"),
        Value::Object(o) => {
            out.push('{');
            for (i, (k, v)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, indent, depth + 1);
                quote(out, k);
                out.push_str(if indent.is_some() { ": " } else { ":" });
                write(out, v, indent, depth + 1);
            }
            newline(out, indent, depth);
            out.push('}');
        }
    }
}

/// A string as `JSON.stringify` writes it: only `"`, `\` and control characters escaped.
pub fn quote(out: &mut String, s: &str) {
    out.push('"');
    let mut from = 0;
    for (i, b) in s.bytes().enumerate() {
        let esc = match b {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            b'\n' => "\\n",
            b'\r' => "\\r",
            b'\t' => "\\t",
            0x08 => "\\b",
            0x0c => "\\f",
            0..=0x1f => "",
            _ => continue,
        };
        out.push_str(&s[from..i]);
        if esc.is_empty() {
            let _ = write!(out, "\\u{b:04x}");
        } else {
            out.push_str(esc);
        }
        from = i + 1;
    }
    out.push_str(&s[from..]);
    out.push('"');
}

/// A number as JavaScript prints it after reading it: `1.0` is `1`, `1e21` is `1e+21`.
fn js_number(raw: &str) -> String {
    let plain = raw.bytes().all(|b| b.is_ascii_digit() || b == b'-');
    if plain && raw.trim_start_matches('-').len() <= 15 && raw != "-0" {
        return raw.to_string();
    }
    let Ok(f) = raw.parse::<f64>() else { return raw.to_string() };
    if f == 0.0 {
        return "0".into();
    }
    if !f.is_finite() {
        return "null".into();
    }
    // Shortest round-trip digits and exponent, then JavaScript's Number::toString layout.
    let sci = format!("{:e}", f.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let k = digits.len() as i32;
    let n = exp.parse::<i32>().unwrap_or(0) + 1;
    let sign = if f < 0.0 { "-" } else { "" };
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let e = if e >= 0 { format!("+{e}") } else { e.to_string() };
        if k == 1 { format!("{digits}e{e}") } else { format!("{}.{}e{e}", &digits[..1], &digits[1..]) }
    };
    format!("{sign}{body}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_deep_nesting_on_a_small_stack() {
        // The limit, not the stack, must stop a hostile document: a quarter of the 2 MiB a pool
        // thread gets is enough, even unoptimized.
        std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(|| {
                let ok = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
                assert!(parse(&ok).is_ok());
                let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
                assert!(parse(&deep).is_err());
                let obj = "{\"a\":".repeat(100_000);
                assert!(parse(&obj).is_err());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    fn round(text: &str) -> String {
        to_string(&parse(text).unwrap())
    }

    #[test]
    fn parses_and_writes_like_javascript() {
        assert_eq!(
            round(r#" {"a" : [1, 2.50, -0, 1e21, 1.5e-7, true, null], "b": {}} "#),
            r#"{"a":[1,2.5,0,1e+21,1.5e-7,true,null],"b":{}}"#
        );
        assert_eq!(round(r#"{"a":1,"b":2,"a":3}"#), r#"{"a":3,"b":2}"#);
        assert_eq!(round(r#""\u00e9\ud83d\ude00\n\u0001/""#), "\"é😀\\n\\u0001/\"");
        assert_eq!(round("12345678901234567890"), "12345678901234567000");
        assert_eq!(round("0.1"), "0.1");
        assert_eq!(round("100"), "100");
    }

    #[test]
    fn pretty_prints_with_any_indent() {
        let v = parse(r#"{"a":[1,{"b":[]}],"c":{}}"#).unwrap();
        assert_eq!(to_pretty(&v, "  "), "{\n  \"a\": [\n    1,\n    {\n      \"b\": []\n    }\n  ],\n  \"c\": {}\n}\n");
        assert_eq!(to_pretty(&Value::from(vec![1u64]), "\t"), "[\n\t1\n]\n");
    }

    #[test]
    fn refuses_what_json_parse_refuses() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "01",
            "1.",
            "-",
            "\"a\nb\"",
            "\"\\x\"",
            "tru",
            "{\"a\" 1}",
            "[1 2]",
            "\"abc",
            "1 2",
            "{'a':1}",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should fail");
        }
        let deep = "[".repeat(100_000);
        assert!(parse(&deep).is_err());
        assert!(Scan::new(&deep).skip().is_err());
    }

    #[test]
    fn finds_quotes_across_word_boundaries() {
        for pad in 0..20 {
            let s = format!("\"{}\\\\\\\"x\\\\\"", "a".repeat(pad));
            let expect = format!("{}\\\"x\\", "a".repeat(pad));
            assert_eq!(parse(&s).unwrap().as_str(), Some(expect.as_str()), "pad {pad}");
            let mut scan = Scan::new(&s);
            scan.skip().unwrap();
            assert_eq!(scan.pos, s.len());
        }
    }

    #[test]
    fn skips_and_spans_without_building() {
        let doc = r#"{"skip":{"x":["}",{"y":"]\"{"}],"z":-1.5e3},"keep":"v","versions":{"1.0.0":{"a":1},"2.0.0":[]}}"#;
        let mut s = Scan::new(doc);
        let mut kept = None;
        let mut spans = Vec::new();
        s.members(|s, key| match key.as_ref() {
            "keep" => {
                kept = Some(s.string()?.into_owned());
                Ok(())
            }
            "versions" => s.members(|s, v| {
                let (a, b) = s.span()?;
                spans.push((v.into_owned(), &doc[a..b]));
                Ok(())
            }),
            _ => s.skip(),
        })
        .unwrap();
        assert_eq!(kept.as_deref(), Some("v"));
        assert_eq!(spans, [("1.0.0".to_string(), r#"{"a":1}"#), ("2.0.0".to_string(), "[]")]);
    }

    #[test]
    fn keeps_member_order_through_edits() {
        let mut v = parse(r#"{"b":1,"a":2}"#).unwrap();
        let Value::Object(o) = &mut v else { unreachable!() };
        o.insert("c", Value::Null);
        o.insert("b", Value::Bool(true));
        o.remove("a");
        assert_eq!(to_string(&v), r#"{"b":true,"c":null}"#);
    }
}

/// `JPM_JSON_BENCH=<dir of kept registry documents> cargo test --release json_bench -- --ignored --nocapture`
#[cfg(test)]
mod bench {
    use super::*;

    fn docs() -> Vec<String> {
        let dir = std::env::var("JPM_JSON_BENCH").expect("set JPM_JSON_BENCH");
        let mut out = Vec::new();
        let mut stack = vec![std::path::PathBuf::from(dir)];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if let Ok(bytes) = std::fs::read(&p) {
                    let at = bytes.iter().position(|b| *b == b'\n').unwrap() + 1;
                    out.push(String::from_utf8(bytes[at..].to_vec()).unwrap());
                }
            }
        }
        out
    }

    #[test]
    #[ignore]
    fn json_bench() {
        let docs = docs();
        let bytes: usize = docs.iter().map(String::len).sum();
        println!("{} documents, {:.1} MB", docs.len(), bytes as f64 / 1e6);
        for round in 0..3 {
            let t = std::time::Instant::now();
            let mut n = 0;
            for d in &docs {
                if let Ok(p) = crate::manifest::Packument::parse(d.as_bytes().to_vec()) {
                    n += p.versions().count();
                }
            }
            let serde = t.elapsed();
            let t = std::time::Instant::now();
            let mut m = 0;
            for d in &docs {
                let mut s = Scan::new(d);
                let _ = s.members(|s, key| match key.as_ref() {
                    "versions" if s.at_object() => s.members(|s, _| {
                        s.span()?;
                        m += 1;
                        Ok(())
                    }),
                    "name" | "modified" => s.string().map(|_| ()),
                    _ => s.skip(),
                });
            }
            let scan = t.elapsed();
            let t = std::time::Instant::now();
            for d in &docs {
                let _ = parse(d);
            }
            let full = t.elapsed();
            println!(
                "round {round}: serde_json packument {serde:?} ({n} versions) | scan {scan:?} ({m}) | full parse {full:?}"
            );
        }
    }
}
