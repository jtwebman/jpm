//! Names: matching the host against subjectAltName (RFC 6125, with no common name fallback),
//! and name constraints (RFC 5280 section 4.2.1.10). Both follow webpki rule for rule.

use std::net::IpAddr;

use super::Code::{self, *};
use crate::der::Reader;

/// A GeneralName (RFC 5280 section 4.2.1.6), as far as the checks care.
#[derive(Clone, Copy)]
enum Name<'a> {
    Dns(&'a [u8]),
    Directory,
    Ip(&'a [u8]),
    Uri,
    /// otherName, rfc822Name, x400Address, ediPartyName or registeredID, by tag number.
    Other(u8),
}

fn general_name<'a>(r: &mut Reader<'a>) -> Result<Name<'a>, Code> {
    let (tag, value) = r.read().ok_or(Encoding)?;
    Ok(match tag {
        0x82 => Name::Dns(value),
        0xa4 => Name::Directory,
        0x87 => Name::Ip(value),
        0x86 => Name::Uri,
        0xa0 | 0x81 | 0xa3 | 0xa5 | 0x88 => Name::Other(tag & 0x1f),
        _ => return Err(Encoding),
    })
}

/// What the server is asked for by.
pub(super) enum Host<'h> {
    Dns(&'h [u8]),
    Ip(IpAddr),
}

impl<'h> Host<'h> {
    /// An IP literal (IPv6 with or without brackets), else a DNS name.
    pub fn new(host: &'h str) -> Self {
        let ip = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            Some(v6) => v6.parse().map(IpAddr::V6).ok(),
            None => host.parse().ok(),
        };
        ip.map_or(Host::Dns(host.as_bytes()), Host::Ip)
    }
}

/// Whether some dNSName or iPAddress in the subjectAltName contents `san` names `host`. A
/// malformed dNSName is skipped; a malformed GeneralName reached before a match is an error.
pub(super) fn check_host(san: Option<&[u8]>, host: &Host) -> Result<(), Code> {
    let mut r = Reader::new(san.unwrap_or_default());
    while !r.is_empty() {
        let found = match (general_name(&mut r)?, host) {
            (Name::Dns(p), Host::Dns(h)) => dns_matches(p, Role::Reference, h) == Ok(true),
            (Name::Ip(p), Host::Ip(IpAddr::V4(h))) => p == h.octets(),
            (Name::Ip(p), Host::Ip(IpAddr::V6(h))) => p == h.octets(),
            _ => false,
        };
        if found {
            return Ok(());
        }
    }
    Err(WrongHost)
}

#[derive(Clone, Copy, PartialEq)]
enum Role {
    /// The host we look for.
    Reference,
    /// A name in a certificate.
    Presented,
    /// A dNSName subtree, permitted (`true`) or excluded.
    Constraint(bool),
}

/// Whether `presented` (from a certificate) matches `reference` in `role`. `Err` when either
/// is not a valid name. This is webpki's `presented_id_matches_reference_id`.
///
/// For the host: case-insensitive equality; a wildcard `*` presented as a whole leftmost label
/// of a name with at least three labels matches one non-empty label; the host may end with a
/// dot. For a constraint: the name equals it or ends with it at a label boundary; one starting
/// with a dot matches only names below it; an empty one matches all.
fn dns_matches(presented: &[u8], role: Role, reference: &[u8]) -> Result<bool, Code> {
    if !valid_dns(presented, Role::Presented, true) || !valid_dns(reference, role, false) {
        return Err(Encoding);
    }
    let (mut p, mut r) = (presented, reference);
    if matches!(role, Role::Constraint(_)) && p.len() > r.len() {
        if r.is_empty() {
            return Ok(true);
        }
        if r[0] == b'.' {
            p = &p[p.len() - r.len()..];
        } else {
            let dot = p.len() - r.len() - 1;
            if p[dot] != b'.' {
                return Ok(false);
            }
            p = &p[dot + 1..];
        }
    }
    // A wildcard stands for the reference's first label. Within permitted subtrees it is
    // compared literally, so `*.example.com` is not taken as inside `example.com`'s subtree
    // except as its own string.
    if p.first() == Some(&b'*') && role != Role::Constraint(true) {
        p = &p[1..];
        loop {
            let Some((_, rest)) = r.split_first() else { return Ok(false) };
            r = rest;
            if r.first() == Some(&b'.') {
                break;
            }
        }
    }
    loop {
        let (Some((&pb, pr)), Some((&rb, rr))) = (p.split_first(), r.split_first()) else {
            return Ok(false);
        };
        if !pb.eq_ignore_ascii_case(&rb) {
            return Ok(false);
        }
        (p, r) = (pr, rr);
        if p.is_empty() {
            if pb == b'.' {
                return Err(Encoding);
            }
            break;
        }
    }
    if !matches!(role, Role::Constraint(_)) && r.first() == Some(&b'.') {
        r = &r[1..];
    }
    Ok(r.is_empty())
}

/// webpki's `is_valid_dns_id`: LDH labels (and `_`) of 1 to 63 bytes, no hyphen at either end
/// of a label, a last label not all digits, at most 253 bytes. A reference may end with a dot;
/// a constraint may be empty or start with a dot; a wildcard `*.` needs three labels.
fn valid_dns(name: &[u8], role: Role, wildcards: bool) -> bool {
    let constraint = matches!(role, Role::Constraint(_));
    if name.len() > 253 {
        return false;
    }
    if constraint && name.is_empty() {
        return true;
    }
    let wildcard = wildcards && name.first() == Some(&b'*');
    let (mut dots, mut label, mut numeric, mut hyphen) = (0, 0, false, false);
    let mut rest = name;
    if wildcard {
        let [b'*', b'.', r @ ..] = name else { return false };
        (rest, dots) = (r, 1);
    }
    let mut first = !wildcard;
    loop {
        let Some((&b, r)) = rest.split_first() else { return false };
        rest = r;
        match b {
            b'-' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                if b == b'-' && label == 0 {
                    return false;
                }
                numeric = b.is_ascii_digit() && (label == 0 || numeric);
                hyphen = b == b'-';
                label += 1;
                if label > 63 {
                    return false;
                }
            }
            b'.' => {
                dots += 1;
                if label == 0 && (!constraint || !first) || hyphen {
                    return false;
                }
                label = 0;
            }
            _ => return false,
        }
        first = false;
        if rest.is_empty() {
            break;
        }
    }
    if label == 0 && role != Role::Reference || hyphen || numeric {
        return false;
    }
    !wildcard || dots + (label != 0) as usize >= 3
}

/// Check the certificates `below` (each one's subjectAltName, and its subject as a
/// directoryName) against the name constraints `nc`, the contents of a NameConstraints
/// SEQUENCE. `budget` counts subtree comparisons.
pub(super) fn check_constraints<'a>(
    nc: &[u8],
    below: impl Iterator<Item = Option<&'a [u8]>>,
    budget: &mut usize,
) -> Result<(), Code> {
    let mut r = Reader::new(nc);
    let mut subtrees = |tag| match r.peek() == Some(tag) {
        true => r.expect(tag).ok_or(Encoding).map(Some),
        false => Ok(None),
    };
    let permitted = subtrees(0xa0)?;
    let excluded = subtrees(0xa1)?;
    if !r.is_empty() {
        return Err(Encoding);
    }
    for san in below {
        let mut names = Reader::new(san.unwrap_or_default());
        while !names.is_empty() {
            conforms(general_name(&mut names)?, permitted, excluded, budget)?;
        }
        // The subject is a directoryName to the constraints, always (webpki does not compare
        // directory names, so any directoryName subtree refuses every certificate below).
        conforms(Name::Directory, permitted, excluded, budget)?;
    }
    Ok(())
}

fn conforms(name: Name, permitted: Option<&[u8]>, excluded: Option<&[u8]>, budget: &mut usize) -> Result<(), Code> {
    for (is_permitted, subtrees) in [(true, permitted), (false, excluded)] {
        let Some(subtrees) = subtrees else { continue };
        let mut r = Reader::new(subtrees);
        let (mut matched, mut mismatched) = (false, false);
        while !r.is_empty() {
            *budget = budget.checked_sub(1).ok_or(TooComplex)?;
            // GeneralSubtree ::= SEQUENCE { base GeneralName, minimum and maximum absent }
            let mut subtree = Reader::new(r.expect(0x30).ok_or(Encoding)?);
            let base = general_name(&mut subtree)?;
            if !subtree.is_empty() {
                return Err(Encoding);
            }
            let hit = match (name, base) {
                (Name::Dns(n), Name::Dns(b)) => dns_matches(n, Role::Constraint(is_permitted), b)?,
                (Name::Ip(n), Name::Ip(b)) => ip_in_subnet(n, b)?,
                (Name::Directory, Name::Directory) | (Name::Uri, Name::Uri) => !is_permitted,
                (Name::Other(a), Name::Other(b)) if a == b => return Err(NameConstraints),
                _ => continue,
            };
            match (is_permitted, hit) {
                (true, true) => matched = true,
                (true, false) => mismatched = true,
                (false, true) => return Err(NameConstraints),
                (false, false) => {}
            }
        }
        if mismatched && !matched {
            return Err(NameConstraints);
        }
    }
    Ok(())
}

/// Whether address `name` (4 or 16 bytes) lies in `subnet`, an address and a mask of
/// contiguous leading ones. An address of the other family does not.
fn ip_in_subnet(name: &[u8], subnet: &[u8]) -> Result<bool, Code> {
    match (name.len(), subnet.len()) {
        (4, 8) | (16, 32) => {}
        (4, 32) | (16, 8) => return Ok(false),
        (4 | 16, _) => return Err(BadMask),
        _ => return Err(Encoding),
    }
    let (addr, mask) = subnet.split_at(name.len());
    let mut zero_seen = false;
    for ((&n, &a), &m) in name.iter().zip(addr).zip(mask) {
        if m.leading_ones() + m.trailing_zeros() != 8 || zero_seen && m != 0 {
            return Err(BadMask);
        }
        zero_seen |= m != 0xff;
        if (n ^ a) & m != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(presented: &str, host: &str) -> bool {
        dns_matches(presented.as_bytes(), Role::Reference, host.as_bytes()) == Ok(true)
    }

    #[test]
    fn host_names() {
        assert!(host("example.com", "example.com"));
        assert!(host("example.com", "EXAMPLE.com"));
        assert!(host("Example.COM", "example.com"));
        assert!(host("example.com", "example.com."));
        assert!(!host("example.com.", "example.com"));
        assert!(!host("example.com", "example.co"));
        assert!(!host("example.com", "www.example.com"));
        assert!(!host("www.example.com", "example.com"));
        assert!(host("*.example.com", "www.example.com"));
        assert!(host("*.example.com", "WWW.example.com."));
        assert!(!host("*.example.com", "example.com"));
        assert!(!host("*.example.com", "a.b.example.com"));
        assert!(!host("*.example.com", ".example.com"));
        assert!(!host("*.com", "example.com"));
        assert!(!host("w*.example.com", "www.example.com"));
        assert!(!host("*w.example.com", "www.example.com"));
        assert!(!host("www.*.com", "www.example.com"));
        assert!(!host("*.example.com", "*.example.com"));
        assert!(!host("example.com", "1.2.3.4"));
        assert!(!host("1.2.3.4", "1.2.3.4"));
        assert!(host("_under.example.com", "_under.example.com"));
        assert!(!host("-a.example.com", "-a.example.com"));
        assert!(!host("a-.example.com", "a-.example.com"));
        assert!(!host("a..com", "a..com"));
        assert!(!host("", ""));
        assert!(host("xn--bcher-kva.example", "xn--bcher-kva.example"));
        let long = "a".repeat(63);
        assert!(host(&format!("{long}.com"), &format!("{long}.com")));
        let too_long = "a".repeat(64);
        assert!(!host(&format!("{too_long}.com"), &format!("{too_long}.com")));
    }

    fn constraint(presented: &str, base: &str, permitted: bool) -> Result<bool, Code> {
        dns_matches(presented.as_bytes(), Role::Constraint(permitted), base.as_bytes())
    }

    #[test]
    fn dns_constraints() {
        assert_eq!(constraint("example.com", "example.com", true), Ok(true));
        assert_eq!(constraint("www.example.com", "example.com", true), Ok(true));
        assert_eq!(constraint("wwwexample.com", "example.com", true), Ok(false));
        assert_eq!(constraint("www.example.com", ".example.com", true), Ok(true));
        assert_eq!(constraint("example.com", ".example.com", true), Ok(false));
        assert_eq!(constraint("anything.org", "", true), Ok(true));
        assert_eq!(constraint("example.org", "example.com", true), Ok(false));
        assert_eq!(constraint("*.example.com", "example.com", false), Ok(true));
        assert_eq!(constraint("*.example.com", "example.com", true), Ok(true));
        assert_eq!(constraint("*.example.com", "www.example.com", true), Ok(false));
        assert_eq!(constraint("*.example.com", "www.example.com", false), Ok(true));
        assert_eq!(constraint("a..com", "example.com", true), Err(Encoding));
        assert_eq!(constraint("example.com", "exa..com", true), Err(Encoding));
    }

    #[test]
    fn subnets() {
        let net = [10, 0, 0, 0, 255, 0, 0, 0];
        assert_eq!(ip_in_subnet(&[10, 1, 2, 3], &net), Ok(true));
        assert_eq!(ip_in_subnet(&[11, 1, 2, 3], &net), Ok(false));
        assert_eq!(ip_in_subnet(&[0; 16], &net), Ok(false));
        assert_eq!(ip_in_subnet(&[10, 1, 2, 3], &[10, 0, 0, 0, 255, 0, 255, 0]), Err(BadMask));
        assert_eq!(ip_in_subnet(&[10, 1, 2, 3], &[10, 0, 0, 0, 0xf0 | 1, 0, 0, 0]), Err(BadMask));
        assert_eq!(ip_in_subnet(&[10, 1, 2, 3], &[10, 0, 0]), Err(BadMask));
        assert_eq!(ip_in_subnet(&[10, 1, 2], &net), Err(Encoding));
        assert_eq!(ip_in_subnet(&[1, 2, 3, 4], &[0; 8]), Ok(true));
    }

    #[test]
    fn hosts() {
        assert!(matches!(Host::new("::1"), Host::Ip(IpAddr::V6(_))));
        assert!(matches!(Host::new("[::1]"), Host::Ip(IpAddr::V6(_))));
        assert!(matches!(Host::new("127.0.0.1"), Host::Ip(IpAddr::V4(_))));
        assert!(matches!(Host::new("example.com"), Host::Dns(_)));
        assert!(matches!(Host::new("[example.com]"), Host::Dns(_)));
        assert!(matches!(Host::new("[127.0.0.1]"), Host::Dns(_)));
    }
}
