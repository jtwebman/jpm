//! Certificate chains made for the purpose, each checked by verify_server and by webpki, which
//! must agree (x509_util::check), and against the expected outcome.

mod x509_util;

use jpm_tls::x509::{self, PublicKey, Scheme};
use rcgen::{
    BasicConstraints, CidrSubnet, CustomExtension, DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa,
    NameConstraints, SanType,
};
use rustls::SignatureScheme;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use x509_util::*;

const EXPIRED: Result<(), &str> = Err("certificate expired");
const NOT_YET: Result<(), &str> = Err("certificate not yet valid");
const WRONG_HOST: Result<(), &str> = Err("certificate is not valid for this host");
const UNKNOWN: Result<(), &str> = Err("unknown issuer");
const BAD_SIG: Result<(), &str> = Err("bad signature");
const UNSUPPORTED: Result<(), &str> = Err("unsupported certificate");
const ENCODING: Result<(), &str> = Err("invalid certificate encoding");
const NC: Result<(), &str> = Err("certificate not allowed by name constraints");
const EKU: Result<(), &str> = Err("certificate is not for server authentication");
const NOT_CA: Result<(), &str> = Err("issuer is not a CA");

fn run(c: &Chain, host: &str) -> Result<(), &'static str> {
    check(&c.ders(), host, NOW, &c.anchors())
}

fn at(c: &Chain, now: u64) -> Result<(), &'static str> {
    check(&c.ders(), "example.com", now, &c.anchors())
}

/// Seconds since the epoch for a date at midnight UTC.
fn date(y: i32, m: u8, d: u8) -> u64 {
    rcgen::date_time_ymd(y, m, d).unix_timestamp() as u64
}

#[test]
fn depths_and_key_types() {
    let sets: &[&[Kind]] = &[
        &[Kind::P256],
        &[Kind::P384],
        &[Kind::P384, Kind::P256],
        &[Kind::Rsa4096, Kind::Rsa3072, Kind::Rsa2048],
        &[Kind::Rsa2048, Kind::P256, Kind::P384],
    ];
    for kinds in sets {
        for n in 0..=6 {
            let c = Chain::new(n, &["example.com"], kinds);
            assert_eq!(run(&c, "example.com"), Ok(()), "{kinds:?} {n}");
        }
    }
}

#[test]
fn seven_intermediates_is_too_many() {
    let c = Chain::new(7, &["example.com"], &[Kind::P256]);
    assert_eq!(run(&c, "example.com"), Err("path too long"));
    // Trusting the top intermediate instead shortens the path to 6.
    let anchors = vec![c.inters[0].anchor()];
    assert_eq!(check(&c.ders(), "example.com", NOW, &anchors), Ok(()));
}

#[test]
fn returns_the_leaf_key() {
    let c = Chain::new(1, &["example.com"], &[Kind::P256]);
    let anchors: Vec<_> = c.anchors();
    let a: Vec<_> = anchors.iter().map(anchor).collect();
    let key = x509::verify_server(&c.ders(), "example.com", NOW, &a).unwrap();
    assert_eq!(key, PublicKey::P256(c.leaf.key.public_key_raw()));

    let c = Chain::new(1, &["example.com"], &[Kind::P384]);
    let anchors: Vec<_> = c.anchors();
    let a: Vec<_> = anchors.iter().map(anchor).collect();
    let key = x509::verify_server(&c.ders(), "example.com", NOW, &a).unwrap();
    assert_eq!(key, PublicKey::P384(c.leaf.key.public_key_raw()));

    let c = Chain::new(1, &["example.com"], &[Kind::Rsa4096, Kind::Rsa3072, Kind::Rsa2048]);
    let anchors: Vec<_> = c.anchors();
    let a: Vec<_> = anchors.iter().map(anchor).collect();
    let PublicKey::Rsa { n, e } = x509::verify_server(&c.ders(), "example.com", NOW, &a).unwrap() else { panic!() };
    assert_eq!((n.len(), e), (256, &[1, 0, 1][..]));
}

#[test]
fn chain_order_duplicates_and_junk() {
    let c = Chain::new(4, &["example.com"], &[Kind::P256]);
    let anchors = c.anchors();
    let other = Chain::new(2, &["example.com"], &[Kind::P256]);
    let junk: &[&[u8]] = &[b"", b"\x30\x00", b"not a certificate", &other.leaf.der, &other.inters[0].der];
    let mut rng = Rng(7);
    for _ in 0..30 {
        let mut rest: Vec<&[u8]> = c.ders()[1..].to_vec();
        for _ in 0..rng.below(4) {
            rest.push(rest[rng.below(rest.len())]);
        }
        for _ in 0..rng.below(4) {
            rest.push(junk[rng.below(junk.len())]);
        }
        rng.shuffle(&mut rest);
        let mut chain = vec![&c.leaf.der[..]];
        chain.extend(rest);
        assert_eq!(check(&chain, "example.com", NOW, &anchors), Ok(()));
    }
    // The leaf alone, or with the intermediates of another chain.
    assert_eq!(check(&[&c.leaf.der], "example.com", NOW, &anchors), UNKNOWN);
    assert_eq!(check(&[&c.leaf.der, &other.inters[1].der], "example.com", NOW, &anchors), UNKNOWN);
    // A missing link.
    let mut chain = c.ders();
    chain.remove(2);
    assert_eq!(check(&chain, "example.com", NOW, &anchors), UNKNOWN);
    // No anchors, or someone else's (with the same name, so the signature is what fails).
    assert_eq!(check(&c.ders(), "example.com", NOW, &[]), UNKNOWN);
    assert_eq!(check(&c.ders(), "example.com", NOW, &other.anchors()), BAD_SIG);
    // The root sent along does not make itself trusted.
    let mut chain = c.ders();
    chain.push(&c.root.der);
    assert_eq!(check(&chain, "example.com", NOW, &other.anchors()), BAD_SIG);
    // An empty chain, and a junk leaf.
    assert_eq!(ours(&[], "example.com", NOW, &anchors), ENCODING);
    assert_eq!(check(&[b"junk"], "example.com", NOW, &anchors), ENCODING);
}

#[test]
fn many_anchors() {
    let c = Chain::new(1, &["example.com"], &[Kind::P256]);
    let mut anchors: Vec<_> = (0..20).map(|_| Chain::new(0, &["x.org"], &[Kind::P256]).root.anchor()).collect();
    anchors.insert(10, c.root.anchor());
    assert_eq!(check(&c.ders(), "example.com", NOW, &anchors), Ok(()));
    // An anchor with the right name and the wrong key does not stop the search.
    let impostor = Node::root(ca_params("root"), Kind::P256).anchor();
    let anchors = vec![impostor.clone(), c.root.anchor()];
    assert_eq!(check(&c.ders(), "example.com", NOW, &anchors), Ok(()));
    assert_eq!(check(&c.ders(), "example.com", NOW, &[impostor]), BAD_SIG);
}

#[test]
fn validity_at_each_level() {
    // Level `k` valid only in 2031; everything else valid 2020 to 2040.
    for k in 0..=3 {
        let c = Chain::custom(2, &["example.com"], &[Kind::P256], |level, p| {
            if level == k {
                p.not_before = rcgen::date_time_ymd(2031, 1, 1);
                p.not_after = rcgen::date_time_ymd(2032, 1, 1);
            }
        });
        let inside = date(2031, 6, 1);
        assert_eq!(at(&c, inside), Ok(()), "{k}");
        // The anchor's own dates do not matter (webpki and browsers alike).
        let (before, after) = if k == 0 { (Ok(()), Ok(())) } else { (NOT_YET, EXPIRED) };
        assert_eq!(at(&c, NOW), before, "{k}");
        assert_eq!(at(&c, date(2033, 1, 1)), after, "{k}");
    }
    let c = Chain::new(1, &["example.com"], &[Kind::P256]);
    assert_eq!(at(&c, date(2019, 12, 31)), NOT_YET);
    assert_eq!(at(&c, date(2041, 1, 1)), EXPIRED);
    assert_eq!(at(&c, 0), NOT_YET);
    assert_eq!(at(&c, u64::MAX), EXPIRED);
}

#[test]
fn validity_boundaries_are_inclusive() {
    let c = Chain::new(0, &["example.com"], &[Kind::P256]);
    let (start, end) = (date(2020, 1, 1), date(2040, 1, 1));
    assert_eq!(at(&c, start - 1), NOT_YET);
    assert_eq!(at(&c, start), Ok(()));
    assert_eq!(at(&c, end), Ok(()));
    assert_eq!(at(&c, end + 1), EXPIRED);
}

#[test]
fn validity_across_2050() {
    // rcgen writes GeneralizedTime from 2050, as RFC 5280 section 4.1.2.5 says.
    let c = Chain::custom(1, &["example.com"], &[Kind::P256], |_, p| {
        p.not_before = rcgen::date_time_ymd(2049, 12, 31);
        p.not_after = rcgen::date_time_ymd(2050, 1, 2);
    });
    assert_eq!(at(&c, date(2050, 1, 1)), Ok(()));
    assert_eq!(at(&c, date(2050, 1, 3)), EXPIRED);
    assert_eq!(at(&c, date(2049, 12, 30)), NOT_YET);
    // Far in the future, and leap days.
    let c = Chain::custom(0, &["example.com"], &[Kind::P256], |_, p| {
        p.not_before = rcgen::date_time_ymd(2400, 2, 29);
        p.not_after = rcgen::date_time_ymd(9999, 12, 31);
    });
    assert_eq!(at(&c, date(2400, 2, 29)), Ok(()));
    assert_eq!(at(&c, date(2400, 2, 28)), NOT_YET);
}

#[test]
fn inverted_validity() {
    let c = Chain::custom(0, &["example.com"], &[Kind::P256], |level, p| {
        if level == 1 {
            p.not_before = rcgen::date_time_ymd(2030, 1, 2);
            p.not_after = rcgen::date_time_ymd(2030, 1, 1);
        }
    });
    assert_eq!(at(&c, NOW), Err("invalid certificate validity"));
}

#[test]
fn hand_written_times() {
    // Rewrite the leaf's validity; `now` is 2030.
    let c = Chain::new(0, &["example.com"], &[Kind::P256]);
    let anchors = c.anchors();
    let with = |nb: &[u8], na: &[u8]| {
        let der = resign(&c.leaf.der, &c.root.key, |f| f[4] = seq(&[nb, na]));
        check(&[&der], "example.com", NOW, &anchors)
    };
    let utc = |s: &str| tlv(0x17, s.as_bytes());
    let gtime = |s: &str| tlv(0x18, s.as_bytes());
    assert_eq!(with(&utc("200101000000Z"), &utc("400101000000Z")), Ok(()));
    assert_eq!(with(&gtime("20200101000000Z"), &gtime("20400101000000Z")), Ok(()));
    // GeneralizedTime before 2050 is allowed, as webpki allows it.
    assert_eq!(with(&utc("200101000000Z"), &gtime("20400101000000Z")), Ok(()));
    // UTCTime 49 is 2049 and 50 is 1950.
    assert_eq!(with(&utc("200101000000Z"), &utc("491231235959Z")), Ok(()));
    assert_eq!(with(&utc("500101000000Z"), &utc("400101000000Z")), ENCODING);
    // Before 1970.
    assert_eq!(with(&gtime("19691231235959Z"), &gtime("20400101000000Z")), ENCODING);
    assert_eq!(with(&gtime("19700101000000Z"), &gtime("20400101000000Z")), Ok(()));
    // Bad forms.
    for bad in [
        utc("2001010000Z"),
        utc("200101000000"),
        utc("200101000000+0000"),
        utc("2001010000000Z"),
        utc("20010100000aZ"),
        utc("201301000000Z"),
        utc("200001000000Z"),
        utc("200100000000Z"),
        utc("200132000000Z"),
        utc("210229000000Z"),
        utc("200101240000Z"),
        utc("200101006000Z"),
        utc("200101000060Z"),
        utc(" 00101000000Z"),
        gtime("20200101000000.5Z"),
        gtime("202001010000Z"),
        gtime("20200101000000z"),
        tlv(0x04, b"200101000000Z"),
        tlv(0x17, b""),
    ] {
        assert_eq!(with(&bad, &utc("400101000000Z")), ENCODING, "{}", hex(&bad));
    }
    // A leap day that exists, and the end of a year.
    assert_eq!(with(&utc("200229000000Z"), &utc("401231235959Z")), Ok(()));
    // Three times, or one.
    assert_eq!(with(&[utc("200101000000Z"), utc("300101000000Z")].concat(), &utc("400101000000Z")), ENCODING);
    let der = resign(&c.leaf.der, &c.root.key, |f| f[4] = seq(&[&utc("200101000000Z")]));
    assert_eq!(check(&[&der], "example.com", NOW, &anchors), ENCODING);
}

#[test]
fn host_names() {
    let names = ["example.com", "*.wild.example.com", "192.0.2.1", "2001:db8::1", "UPPER.example.com"];
    let c = Chain::new(1, &names, &[Kind::P256]);
    for (host, want) in [
        ("example.com", Ok(())),
        ("EXAMPLE.com", Ok(())),
        ("example.com.", Ok(())),
        ("upper.EXAMPLE.com", Ok(())),
        ("www.example.com", WRONG_HOST),
        ("xample.com", WRONG_HOST),
        ("example.co", WRONG_HOST),
        ("example.com..", WRONG_HOST),
        (".example.com", WRONG_HOST),
        ("a.wild.example.com", Ok(())),
        ("A-1.wild.example.com", Ok(())),
        ("wild.example.com", WRONG_HOST),
        ("a.b.wild.example.com", WRONG_HOST),
        ("*.wild.example.com", WRONG_HOST),
        ("192.0.2.1", Ok(())),
        ("192.0.2.2", WRONG_HOST),
        ("::ffff:192.0.2.1", WRONG_HOST),
        ("2001:db8::1", Ok(())),
        ("[2001:db8::1]", Ok(())),
        ("2001:0db8:0:0:0:0:0:1", Ok(())),
        ("2001:db8::2", WRONG_HOST),
        ("[192.0.2.1]", WRONG_HOST),
        ("", WRONG_HOST),
        ("exa mple.com", WRONG_HOST),
        ("example.com/", WRONG_HOST),
    ] {
        assert_eq!(run(&c, host), want, "{host}");
    }
}

#[test]
fn wildcards() {
    let names = ["*.com", "*.a.b", "*.c.example.org", "x*.example.net", "*"];
    let c = Chain::new(0, &names, &[Kind::P256]);
    for (host, want) in [
        ("example.com", WRONG_HOST),
        ("x.a.b", Ok(())),
        ("a.b", WRONG_HOST),
        ("d.c.example.org", Ok(())),
        ("xy.example.net", WRONG_HOST),
        ("x.example.net", WRONG_HOST),
        ("anything", WRONG_HOST),
    ] {
        assert_eq!(run(&c, host), want, "{host}");
    }
}

#[test]
fn names_by_type() {
    // A dNSName that looks like an address does not match the address, and the other way.
    let c = Chain::custom(0, &[], &[Kind::P256], |level, p| {
        if level == 1 {
            p.subject_alt_names = vec![
                SanType::DnsName("192.0.2.7".try_into().unwrap()),
                SanType::IpAddress("192.0.2.8".parse().unwrap()),
                SanType::URI("https://uri.example.com/".try_into().unwrap()),
                SanType::Rfc822Name("mail@example.com".try_into().unwrap()),
            ];
        }
    });
    assert_eq!(run(&c, "192.0.2.7"), WRONG_HOST);
    assert_eq!(run(&c, "192.0.2.8"), Ok(()));
    assert_eq!(run(&c, "uri.example.com"), WRONG_HOST);
    assert_eq!(run(&c, "example.com"), WRONG_HOST);
}

#[test]
fn common_name_is_not_used() {
    let c = Chain::custom(1, &[], &[Kind::P256], |level, p| {
        if level == 2 {
            p.distinguished_name.push(DnType::CommonName, "example.com");
        }
    });
    assert_eq!(run(&c, "example.com"), WRONG_HOST);
}

#[test]
fn path_length_constraints() {
    let with = |n: usize, at: usize, len: u8| {
        let c = Chain::custom(n, &["example.com"], &[Kind::P256], |level, p| {
            if level == at {
                p.is_ca = IsCa::Ca(BasicConstraints::Constrained(len));
            }
        });
        run(&c, "example.com")
    };
    let violated = Err("path length constraint violated");
    // Intermediate 1 of 3 (from the root) has two CAs below it.
    assert_eq!(with(3, 1, 0), violated);
    assert_eq!(with(3, 1, 1), violated);
    assert_eq!(with(3, 1, 2), Ok(()));
    assert_eq!(with(3, 1, 255), Ok(()));
    assert_eq!(with(3, 3, 0), Ok(()));
    assert_eq!(with(3, 2, 0), violated);
    assert_eq!(with(3, 2, 1), Ok(()));
    // The root is the anchor, and anchors are not held to their own constraints.
    assert_eq!(with(3, 0, 0), Ok(()));
}

#[test]
fn basic_constraints() {
    let with = |at: usize, is_ca: IsCa| {
        let c = Chain::custom(2, &["example.com"], &[Kind::P256], |level, p| {
            if level == at {
                p.is_ca = is_ca;
            }
        });
        run(&c, "example.com")
    };
    assert_eq!(with(1, IsCa::ExplicitNoCa), NOT_CA);
    assert_eq!(with(2, IsCa::NoCa), NOT_CA);
    assert_eq!(with(0, IsCa::NoCa), Ok(()));
    assert_eq!(with(3, IsCa::Ca(BasicConstraints::Unconstrained)), Err("CA certificate used as a server certificate"));
    assert_eq!(with(3, IsCa::ExplicitNoCa), Ok(()));
}

#[test]
fn self_signed_leaf_as_anchor() {
    let mut p = leaf_params(&["example.com"]);
    p.distinguished_name.push(DnType::OrganizationName, "self");
    let leaf = Node::root(p, Kind::P256);
    assert_eq!(check(&[&leaf.der], "example.com", NOW, &[leaf.anchor()]), Ok(()));
    assert_eq!(check(&[&leaf.der], "example.com", NOW, &[]), UNKNOWN);
}

#[test]
fn extended_key_usage() {
    use ExtendedKeyUsagePurpose::*;
    let with = |at: usize, ekus: Vec<ExtendedKeyUsagePurpose>| {
        let c = Chain::custom(1, &["example.com"], &[Kind::P256], |level, p| {
            if level == at {
                p.extended_key_usages = ekus.clone();
            }
        });
        run(&c, "example.com")
    };
    assert_eq!(with(2, vec![]), Ok(()));
    assert_eq!(with(2, vec![ServerAuth]), Ok(()));
    assert_eq!(with(2, vec![ClientAuth, ServerAuth]), Ok(()));
    assert_eq!(with(2, vec![ClientAuth]), EKU);
    assert_eq!(with(2, vec![Any]), EKU);
    assert_eq!(with(2, vec![CodeSigning, EmailProtection]), EKU);
    assert_eq!(with(1, vec![ServerAuth, ClientAuth]), Ok(()));
    assert_eq!(with(1, vec![ClientAuth]), EKU);
    assert_eq!(with(1, vec![Any]), EKU);
    assert_eq!(with(0, vec![ClientAuth]), Ok(()));
    // An empty list, written by hand.
    let c = Chain::new(0, &["example.com"], &[Kind::P256]);
    let der = resign(&c.leaf.der, &c.root.key, |f| {
        let mut exts = extensions(&c.leaf.der);
        exts.retain(|e| !e.windows(3).any(|w| w == [0x55, 0x1d, 37]));
        exts.push(extension(&[0x55, 0x1d, 37], false, &seq(&[])));
        set_extensions(f, &exts);
    });
    assert_eq!(check(&[&der], "example.com", NOW, &c.anchors()), EKU);
}

#[test]
fn unknown_extensions() {
    let with = |at: usize, critical: bool| {
        let c = Chain::custom(1, &["example.com"], &[Kind::P256], |level, p| {
            if level == at {
                let mut ext = CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 1], vec![5, 0]);
                ext.set_criticality(critical);
                p.custom_extensions.push(ext);
            }
        });
        run(&c, "example.com")
    };
    for level in 1..=2 {
        assert_eq!(with(level, false), Ok(()));
        assert_eq!(with(level, true), UNSUPPORTED);
    }
    // Anchors are not parsed again: a root with one is still trusted.
    assert_eq!(with(0, true), Ok(()));
}

#[test]
fn extensions_by_hand() {
    let c = Chain::new(0, &["example.com"], &[Kind::P256]);
    let anchors = c.anchors();
    let exts = extensions(&c.leaf.der);
    let with = |exts: Vec<Vec<u8>>| {
        let der = resign(&c.leaf.der, &c.root.key, |f| set_extensions(f, &exts));
        check(&[&der], "example.com", NOW, &anchors)
    };
    let find = |id: u8| exts.iter().find(|e| e.windows(3).any(|w| w == [0x55, 0x1d, id])).unwrap().clone();
    let san = find(17);
    assert_eq!(with(exts.clone()), Ok(()));
    // A known extension twice.
    assert_eq!(with([exts.clone(), vec![san.clone()]].concat()), ENCODING);
    // An unknown one twice is let through, as webpki does: nothing reads it.
    let unknown = extension(&[0x2b, 6, 1, 4, 1, 1], false, &[5, 0]);
    assert_eq!(with([exts.clone(), vec![unknown.clone(), unknown]].concat()), Ok(()));
    // Critical: unknown refused, known accepted, and an unknown id-ce one refused.
    assert_eq!(with([exts.clone(), vec![extension(&[0x2b, 6, 1, 4, 1, 1], true, &[5, 0])]].concat()), UNSUPPORTED);
    assert_eq!(with([exts.clone(), vec![extension(&[0x55, 0x1d, 32], true, &seq(&[]))]].concat()), UNSUPPORTED);
    assert_eq!(with([exts.clone(), vec![extension(&[0x55, 0x1d, 14], false, &[4, 1, 0])]].concat()), Ok(()));
    let body = Reader(&san).fields();
    let crit_san = seq(&[&body[0], &tlv(1, &[0xff]), &body[1]]);
    let rest: Vec<_> = exts.iter().filter(|e| **e != san).cloned().collect();
    assert_eq!(with([rest.clone(), vec![crit_san]].concat()), Ok(()));
    // An explicit FALSE is accepted, as webpki accepts it; other BOOLEAN values are not.
    assert_eq!(with([rest.clone(), vec![seq(&[&body[0], &tlv(1, &[0]), &body[1]])]].concat()), Ok(()));
    assert_eq!(with([rest.clone(), vec![seq(&[&body[0], &tlv(1, &[1]), &body[1]])]].concat()), ENCODING);
    assert_eq!(with([rest.clone(), vec![seq(&[&body[0], &tlv(1, &[]), &body[1]])]].concat()), ENCODING);
    // Trailing data in an extension, and in a known extension's value.
    assert_eq!(with([rest.clone(), vec![seq(&[&body[0], &body[1], &[5, 0]])]].concat()), ENCODING);
    let mut value = Reader(&body[1]).contents();
    value.extend([5, 0]);
    assert_eq!(with([rest.clone(), vec![seq(&[&body[0], &tlv(4, &value)])]].concat()), ENCODING);
    // keyUsage is not read at all: garbage in it passes, as in webpki.
    let mut no_ku = exts.clone();
    no_ku.retain(|e| !e.windows(3).any(|w| w == [0x55, 0x1d, 15]));
    assert_eq!(with([no_ku, vec![extension(&[0x55, 0x1d, 15], true, b"garbage")]].concat()), Ok(()));
    // No extensions: the name cannot match. An empty list is allowed.
    assert_eq!(with(vec![]), WRONG_HOST);
    let der = resign(&c.leaf.der, &c.root.key, |f| f.retain(|f| f[0] != 0xa3));
    assert_eq!(check(&[&der], "example.com", NOW, &anchors), WRONG_HOST);
}

/// A tiny helper over one TLV, for the tests above.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    /// The TLVs inside this one, whole.
    fn fields(&self) -> Vec<Vec<u8>> {
        let mut r = jpm_tls::der::Reader::new(jpm_tls::der::Reader::new(self.0).read().unwrap().1);
        let mut out = Vec::new();
        while !r.is_empty() {
            let before = r.rest();
            r.read().unwrap();
            out.push(before[..before.len() - r.rest().len()].to_vec());
        }
        out
    }

    fn contents(&self) -> Vec<u8> {
        jpm_tls::der::Reader::new(self.0).read().unwrap().1.to_vec()
    }
}

#[test]
fn certificate_structure() {
    let c = Chain::new(0, &["example.com"], &[Kind::P256]);
    let anchors = c.anchors();
    let with = |edit: &dyn Fn(&mut Vec<Vec<u8>>)| {
        let der = resign(&c.leaf.der, &c.root.key, edit);
        check(&[&der], "example.com", NOW, &anchors)
    };
    assert_eq!(with(&|_| {}), Ok(()));
    // Versions 1 and 2.
    assert_eq!(with(&|f| drop(f.remove(0))), UNSUPPORTED);
    assert_eq!(with(&|f| f[0] = tlv(0xa0, &[2, 1, 1])), UNSUPPORTED);
    assert_eq!(with(&|f| f[0] = tlv(0xa0, &[2, 1, 3])), UNSUPPORTED);
    assert_eq!(with(&|f| f[0] = tlv(0xa0, &[2, 2, 0, 2])), UNSUPPORTED);
    // Serial numbers are not judged, as webpki does not judge them.
    for serial in [&[0][..], &[0xff], &[0x80, 1], &[1; 21], &[0, 0x80], &[0, 1], &[]] {
        assert_eq!(with(&|f| f[1] = tlv(2, serial)), Ok(()), "{serial:?}");
    }
    assert_eq!(with(&|f| f[1] = tlv(4, &[1])), ENCODING);
    // Unique identifiers (RFC 5280 section 4.1.2.8) are refused, as webpki refuses them.
    assert_eq!(with(&|f| f.insert(7, tlv(0x81, &[0, 1]))), ENCODING);
    assert_eq!(with(&|f| f.insert(7, tlv(0x82, &[0, 1]))), ENCODING);
    // Trailing data in the TBS, a second [3], an empty [3].
    assert_eq!(with(&|f| f.push(tlv(5, &[]))), ENCODING);
    assert_eq!(with(&|f| f.push(f[7].clone())), ENCODING);
    assert_eq!(with(&|f| f[7] = tlv(0xa3, &[])), ENCODING);
    // A missing field.
    assert_eq!(with(&|f| drop(f.remove(5))), ENCODING);
    // Names are compared as bytes: re-encoding the issuer breaks the link.
    assert_eq!(with(&|f| f[3] = seq(&[])), UNKNOWN);
}

#[test]
fn outer_structure() {
    let c = Chain::new(0, &["example.com"], &[Kind::P256]);
    let anchors = c.anchors();
    let parts = Reader(&c.leaf.der).fields();
    let with = |der: Vec<u8>| check(&[&der], "example.com", NOW, &anchors);
    assert_eq!(with(seq(&[&parts[0], &parts[1], &parts[2]])), Ok(()));
    assert_eq!(with([c.leaf.der.clone(), vec![0]].concat()), ENCODING);
    assert_eq!(with(seq(&[&parts[0], &parts[1], &parts[2], &[5, 0]])), ENCODING);
    assert_eq!(with(seq(&[&parts[0], &parts[1]])), ENCODING);
    // Unused bits in the signature.
    let mut sig = Reader(&parts[2]).contents();
    sig[0] = 1;
    assert_eq!(with(seq(&[&parts[0], &parts[1], &tlv(3, &sig)])), ENCODING);
    // The outer algorithm must equal the TBS one.
    let other = tlv(0x30, &hex_bytes("06082a8648ce3d040303"));
    assert_eq!(with(seq(&[&parts[0], &other, &parts[2]])), BAD_SIG);
    // Truncations.
    for n in 0..c.leaf.der.len() {
        assert!(with(c.leaf.der[..n].to_vec()).is_err());
    }
}

#[test]
fn name_constraints_dns() {
    let nc = |permitted: &[&str], excluded: &[&str]| NameConstraints {
        permitted_subtrees: permitted.iter().map(|s| GeneralSubtree::DnsName(s.to_string())).collect(),
        excluded_subtrees: excluded.iter().map(|s| GeneralSubtree::DnsName(s.to_string())).collect(),
    };
    let with = |at: usize, c: NameConstraints, names: &[&str]| {
        let chain = Chain::custom(2, names, &[Kind::P256], |level, p| {
            if level == at {
                p.name_constraints = Some(c.clone());
            }
        });
        run(&chain, &names[0].replace('*', "a"))
    };
    for at in [0, 1, 2] {
        assert_eq!(with(at, nc(&["example.com"], &[]), &["www.example.com"]), Ok(()), "{at}");
        assert_eq!(with(at, nc(&["example.com"], &[]), &["example.com"]), Ok(()), "{at}");
        assert_eq!(with(at, nc(&["example.com"], &[]), &["example.org"]), NC, "{at}");
        assert_eq!(with(at, nc(&["example.com"], &[]), &["badexample.com"]), NC, "{at}");
        assert_eq!(with(at, nc(&["example.com"], &[]), &["a.example.com", "evil.org"]), NC, "{at}");
        assert_eq!(with(at, nc(&["example.com", "example.org"], &[]), &["a.example.org"]), Ok(()), "{at}");
        assert_eq!(with(at, nc(&[".example.com"], &[]), &["example.com"]), NC, "{at}");
        assert_eq!(with(at, nc(&[".example.com"], &[]), &["a.example.com"]), Ok(()), "{at}");
        assert_eq!(with(at, nc(&[], &["evil.example.com"]), &["evil.example.com"]), NC, "{at}");
        assert_eq!(with(at, nc(&[], &["evil.example.com"]), &["x.evil.example.com"]), NC, "{at}");
        assert_eq!(with(at, nc(&[], &["evil.example.com"]), &["good.example.com"]), Ok(()), "{at}");
        assert_eq!(with(at, nc(&["example.com"], &["evil.example.com"]), &["evil.example.com"]), NC, "{at}");
        assert_eq!(with(at, nc(&[], &["example.com"]), &["*.example.com"]), NC, "{at}");
        assert_eq!(with(at, nc(&["example.com"], &[]), &["*.example.com"]), Ok(()), "{at}");
        // Only dNSNames are held to dNSName constraints.
        assert_eq!(with(at, nc(&["example.com"], &[]), &["192.0.2.1"]), Ok(()), "{at}");
    }
    // A certificate is not held to its own constraints.
    let chain = Chain::custom(1, &["example.com"], &[Kind::P256], |level, p| {
        if level == 1 {
            p.name_constraints = Some(nc(&["example.com"], &[]));
            p.subject_alt_names = vec![SanType::DnsName("elsewhere.org".try_into().unwrap())];
        }
    });
    assert_eq!(run(&chain, "example.com"), Ok(()));
    // But an intermediate is held to the ones above it.
    let chain = Chain::custom(2, &["example.com"], &[Kind::P256], |level, p| {
        if level == 1 {
            p.name_constraints = Some(nc(&["example.com"], &[]));
        }
        if level == 2 {
            p.subject_alt_names = vec![SanType::DnsName("elsewhere.org".try_into().unwrap())];
        }
    });
    assert_eq!(run(&chain, "example.com"), NC);
}

#[test]
fn name_constraints_ip_and_others() {
    let net = |s: &str, prefix: u8| GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(s.parse().unwrap(), prefix));
    let with = |permitted: Vec<GeneralSubtree>, excluded: Vec<GeneralSubtree>, names: &[&str]| {
        let chain = Chain::custom(1, names, &[Kind::P256], |level, p| {
            if level == 0 {
                p.name_constraints = Some(NameConstraints {
                    permitted_subtrees: permitted.clone(),
                    excluded_subtrees: excluded.clone(),
                });
            }
        });
        run(&chain, names[0])
    };
    assert_eq!(with(vec![net("192.0.2.0", 24)], vec![], &["192.0.2.9"]), Ok(()));
    assert_eq!(with(vec![net("192.0.2.0", 24)], vec![], &["192.0.3.9"]), NC);
    assert_eq!(with(vec![net("192.0.2.0", 24)], vec![], &["example.com"]), Ok(()));
    assert_eq!(with(vec![net("192.0.2.0", 24)], vec![], &["2001:db8::1"]), NC);
    assert_eq!(with(vec![net("192.0.2.0", 25)], vec![], &["192.0.2.128"]), NC);
    assert_eq!(with(vec![net("0.0.0.0", 0)], vec![], &["203.0.113.1"]), Ok(()));
    assert_eq!(with(vec![], vec![net("192.0.2.0", 24)], &["192.0.2.9"]), NC);
    assert_eq!(with(vec![], vec![net("192.0.2.0", 24)], &["192.0.3.9"]), Ok(()));
    assert_eq!(with(vec![net("2001:db8::", 32)], vec![], &["2001:db8:1::1"]), Ok(()));
    assert_eq!(with(vec![net("2001:db8::", 32)], vec![], &["2001:db9::1"]), NC);
    assert_eq!(with(vec![], vec![net("2001:db8::", 48)], &["2001:db8:0:1::1"]), NC);
    assert_eq!(with(vec![net("2001:db8::", 32), net("192.0.2.0", 24)], vec![], &["192.0.2.1", "2001:db8::5"]), Ok(()));
    // Any directoryName constraint refuses everything below it, as webpki does not compare
    // directory names.
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(DnType::CommonName, "leaf");
    assert_eq!(with(vec![GeneralSubtree::DirectoryName(dn.clone())], vec![], &["example.com"]), NC);
    assert_eq!(with(vec![], vec![GeneralSubtree::DirectoryName(dn)], &["example.com"]), NC);
    // An rfc822Name constraint refuses a certificate with an rfc822Name, whatever its value.
    let chain = Chain::custom(1, &["example.com"], &[Kind::P256], |level, p| {
        if level == 0 {
            p.name_constraints = Some(NameConstraints {
                permitted_subtrees: vec![GeneralSubtree::Rfc822Name("example.com".into())],
                excluded_subtrees: vec![],
            });
        }
        if level == 2 {
            p.subject_alt_names.push(SanType::Rfc822Name("a@example.com".try_into().unwrap()));
        }
    });
    assert_eq!(run(&chain, "example.com"), NC);
}

#[test]
fn name_constraints_by_hand() {
    // Constraints on an anchor, as bytes.
    let c = Chain::new(1, &["www.example.com", "192.0.2.1"], &[Kind::P256]);
    let root = c.root.anchor();
    let with = |nc: Vec<u8>| {
        let mut a = root.clone();
        a.name_constraints = Some(nc.into());
        check(&c.ders(), "www.example.com", NOW, &[a])
    };
    let dns = |s: &str| seq(&[&tlv(0x82, s.as_bytes())]);
    assert_eq!(with(tlv(0xa0, &dns("example.com"))), Ok(()));
    assert_eq!(with(vec![]), Ok(()));
    assert_eq!(with(tlv(0xa0, &[])), Ok(()));
    assert_eq!(with(tlv(0xa0, &dns(""))), Ok(()));
    assert_eq!(with(tlv(0xa1, &dns(""))), NC);
    assert_eq!(with(tlv(0xa0, &dns("EXAMPLE.COM"))), Ok(()));
    assert_eq!(with(tlv(0xa0, &dns("exa mple.com"))), ENCODING);
    assert_eq!(with(tlv(0xa0, &dns("example.com."))), ENCODING);
    // Excluded before permitted, trailing data, a subtree with minimum or maximum.
    assert_eq!(with([tlv(0xa1, &dns("x.org")), tlv(0xa0, &dns("example.com"))].concat()), ENCODING);
    assert_eq!(with([tlv(0xa0, &dns("example.com")), vec![5, 0]].concat()), ENCODING);
    let min = seq(&[&tlv(0x82, b"example.com"), &tlv(0x80, &[0])]);
    assert_eq!(with(tlv(0xa0, &min)), ENCODING);
    // Bad masks and lengths for iPAddress subtrees.
    let ip = |b: &[u8]| seq(&[&tlv(0x87, b)]);
    assert_eq!(with(tlv(0xa0, &ip(&[192, 0, 2, 0, 255, 255, 255, 0]))), Ok(()));
    assert_eq!(with(tlv(0xa0, &ip(&[192, 0, 2, 0, 255, 0, 255, 0]))), Err("invalid name constraint"));
    assert_eq!(with(tlv(0xa0, &ip(&[192, 0, 2, 0, 255, 255, 255]))), Err("invalid name constraint"));
    // An unknown GeneralName tag.
    assert_eq!(with(tlv(0xa0, &seq(&[&tlv(0x89, b"x")]))), ENCODING);
}

#[test]
fn wrong_key_and_tampering() {
    let c = Chain::new(1, &["example.com"], &[Kind::P256]);
    let anchors = c.anchors();
    // A leaf signed by a key other than its issuer's.
    let impostor = Node::root(ca_params("intermediate 0"), Kind::P256);
    let leaf = impostor.sign(leaf_params(&["example.com"]), Kind::P256);
    assert_eq!(check(&[&leaf.der, &c.inters[0].der], "example.com", NOW, &anchors), BAD_SIG);
    // A byte changed in the leaf's name, in an intermediate's, and in a signature.
    let flip = |der: &[u8], needle: &[u8]| {
        let mut d = der.to_vec();
        let i = d.windows(needle.len()).position(|w| w == needle).unwrap();
        d[i] ^= 1;
        d
    };
    let leaf = flip(&c.leaf.der, b"example.com");
    assert_eq!(check(&[&leaf, &c.inters[0].der], "example.com", NOW, &anchors), BAD_SIG);
    let mut inter = c.inters[0].der.clone();
    let serial = range_of(&c.inters[0].der, tbs_fields(&c.inters[0].der).unwrap()[1].1);
    inter[serial.end - 1] ^= 1;
    assert_eq!(check(&[&c.leaf.der, &inter], "example.com", NOW, &anchors), BAD_SIG);
    let mut leaf = c.leaf.der.clone();
    let n = leaf.len();
    leaf[n - 5] ^= 0x10;
    assert_eq!(check(&[&leaf, &c.inters[0].der], "example.com", NOW, &anchors), BAD_SIG);
}

#[test]
fn ed25519() {
    // An Ed25519 CA is not supported.
    let c = Chain::new(1, &["example.com"], &[Kind::Ed25519, Kind::P256, Kind::P256]);
    assert_eq!(run(&c, "example.com"), UNSUPPORTED);
    // An Ed25519 leaf key: webpki accepts the path (it never reads the leaf's key), but
    // verify_server must return a key the handshake can use. Difference 1.
    let c = Chain::new(1, &["example.com"], &[Kind::P256, Kind::P256, Kind::Ed25519]);
    assert_eq!(run(&c, "example.com"), UNSUPPORTED);
}

fn signer(kind: Kind, scheme: SignatureScheme) -> Box<dyn rustls::sign::Signer> {
    let der = match kind {
        Kind::Rsa2048 => rsa_pkcs8(2048),
        Kind::Rsa3072 => rsa_pkcs8(3072),
        Kind::Rsa4096 => rsa_pkcs8(4096),
        _ => unreachable!(),
    };
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der));
    rustls::crypto::ring::sign::any_supported_type(&key).unwrap().choose_scheme(&[scheme]).unwrap()
}

#[test]
fn rsa_signature_encodings() {
    // An RSA intermediate signs the leaf in each way.
    let c = Chain::new(1, &["example.com"], &[Kind::P256, Kind::Rsa3072, Kind::P256]);
    let anchors = c.anchors();
    let pss = |hash: u8, salt: u8| {
        let h = format!("300d06096086480165030402{hash:02x}0500");
        hex_bytes(&format!("304106092a864886f70d01010a3034a00f{h}a11c301a06092a864886f70d010108{h}a2030201{salt:02x}"))
    };
    let cases = [
        (hex_bytes("300d06092a864886f70d01010b0500"), SignatureScheme::RSA_PKCS1_SHA256, Ok(())),
        (hex_bytes("300b06092a864886f70d01010b"), SignatureScheme::RSA_PKCS1_SHA256, Ok(())),
        (hex_bytes("300d06092a864886f70d01010c0500"), SignatureScheme::RSA_PKCS1_SHA384, Ok(())),
        (hex_bytes("300b06092a864886f70d01010c"), SignatureScheme::RSA_PKCS1_SHA384, Ok(())),
        (hex_bytes("300d06092a864886f70d01010d0500"), SignatureScheme::RSA_PKCS1_SHA512, Ok(())),
        (hex_bytes("300b06092a864886f70d01010d"), SignatureScheme::RSA_PKCS1_SHA512, Ok(())),
        (pss(1, 32), SignatureScheme::RSA_PSS_SHA256, Ok(())),
        (pss(2, 48), SignatureScheme::RSA_PSS_SHA384, Ok(())),
        (pss(3, 64), SignatureScheme::RSA_PSS_SHA512, Ok(())),
        // The wrong hash for the algorithm named.
        (hex_bytes("300d06092a864886f70d01010b0500"), SignatureScheme::RSA_PKCS1_SHA384, BAD_SIG),
        (pss(1, 32), SignatureScheme::RSA_PKCS1_SHA256, BAD_SIG),
        (hex_bytes("300d06092a864886f70d01010b0500"), SignatureScheme::RSA_PSS_SHA256, BAD_SIG),
        // PSS parameters other than the ones webpki takes.
        (pss(1, 20), SignatureScheme::RSA_PSS_SHA256, UNSUPPORTED),
        (pss(2, 32), SignatureScheme::RSA_PSS_SHA384, UNSUPPORTED),
        (hex_bytes("300b06092a864886f70d01010a"), SignatureScheme::RSA_PSS_SHA256, UNSUPPORTED),
        // Other parameters for PKCS#1, and SHA-1 and MD5.
        (hex_bytes("300f06092a864886f70d01010b04020500"), SignatureScheme::RSA_PKCS1_SHA256, UNSUPPORTED),
        (hex_bytes("300d06092a864886f70d0101050500"), SignatureScheme::RSA_PKCS1_SHA256, UNSUPPORTED),
        (hex_bytes("300d06092a864886f70d0101040500"), SignatureScheme::RSA_PKCS1_SHA256, UNSUPPORTED),
        // An ECDSA algorithm with an RSA key.
        (hex_bytes("300a06082a8648ce3d040302"), SignatureScheme::RSA_PKCS1_SHA256, UNSUPPORTED),
    ];
    for (alg, scheme, want) in cases {
        let s = signer(Kind::Rsa3072, scheme);
        let leaf = resign_with(&c.leaf.der, &alg, |tbs| s.sign(tbs).unwrap());
        let got = check(&[&leaf, &c.inters[0].der], "example.com", NOW, &anchors);
        assert_eq!(got, want, "{} {scheme:?}", hex(&alg));
    }
}

#[test]
fn ecdsa_signature_encodings() {
    let c = Chain::new(1, &["example.com"], &[Kind::P256, Kind::P256, Kind::P256]);
    let anchors = c.anchors();
    let sign = |alg: &str| {
        let leaf =
            resign_with(&c.leaf.der, &hex_bytes(alg), |tbs| rcgen::SigningKey::sign(&c.inters[0].key, tbs).unwrap());
        check(&[&leaf, &c.inters[0].der], "example.com", NOW, &anchors)
    };
    assert_eq!(sign("300a06082a8648ce3d040302"), Ok(()));
    // Parameters present, even NULL.
    assert_eq!(sign("300c06082a8648ce3d0403020500"), UNSUPPORTED);
    // The right name with the wrong hash.
    assert_eq!(sign("300a06082a8648ce3d040303"), BAD_SIG);
    // ecdsa-with-SHA1, and an RSA algorithm with an EC key.
    assert_eq!(sign("300906072a8648ce3d0401"), UNSUPPORTED);
    assert_eq!(sign("300d06092a864886f70d01010b0500"), UNSUPPORTED);
}

#[test]
fn openssl_made() {
    // gen.sh made these; `now` is 2030. See x509_util::difference for the ECDSA SHA-512 ones.
    for (name, want) in [
        ("rsa-sha256", Ok(())),
        ("rsa-sha1", UNSUPPORTED),
        ("p256-sha1", UNSUPPORTED),
        ("p256-sha384", Ok(())),
        ("p256-sha512", Ok(())),
        ("p384-sha256", Ok(())),
        ("p384-sha512", Ok(())),
        ("pss-sha256", Ok(())),
        ("pss-sha384", Ok(())),
        ("pss-sha512", Ok(())),
        ("pss-salt20", UNSUPPORTED),
        ("pss-mgf-sha1", UNSUPPORTED),
    ] {
        let path = format!("{}/tests/data/x509/{name}.pem", env!("CARGO_MANIFEST_DIR"));
        let certs = pem_certs(&std::fs::read_to_string(path).unwrap());
        let anchors = vec![trust(&certs[1])];
        assert_eq!(check(&[&certs[0]], "example.com", NOW, &anchors), want, "{name}");
        assert_eq!(check(&[&certs[0]], "example.org", NOW, &anchors), want.and(WRONG_HOST), "{name}");
    }
}

#[test]
fn verify_signature_pairs() {
    // Key and scheme pairings, on the signatures in gen.sh's certificates.
    let load = |name: &str| {
        pem_certs(
            &std::fs::read_to_string(format!("{}/tests/data/x509/{name}.pem", env!("CARGO_MANIFEST_DIR"))).unwrap(),
        )
    };
    let key_of = |cert: &[u8]| -> Vec<u8> { spki(cert).unwrap().to_vec() };
    use Scheme::*;
    for (name, scheme) in [
        ("rsa-sha256", RsaPkcs1Sha256),
        ("p256-sha384", EcdsaSha384),
        ("p256-sha512", EcdsaSha512),
        ("p384-sha256", EcdsaSha256),
        ("p384-sha512", EcdsaSha512),
        ("pss-sha256", RsaPssSha256),
        ("pss-sha384", RsaPssSha384),
        ("pss-sha512", RsaPssSha512),
    ] {
        let certs = load(name);
        let parts = Reader(&certs[0]).fields();
        let (tbs, sig) = (&parts[0], &Reader(&parts[2]).contents()[1..]);
        let root_spki = key_of(&certs[1]);
        let key = public_key(&root_spki);
        assert!(x509::verify_signature(&key, scheme, tbs, sig), "{name}");
        let mut bad = tbs.clone();
        bad[10] ^= 1;
        assert!(!x509::verify_signature(&key, scheme, &bad, sig), "{name}");
        for other in [
            RsaPkcs1Sha256,
            RsaPkcs1Sha384,
            RsaPkcs1Sha512,
            RsaPssSha256,
            RsaPssSha384,
            RsaPssSha512,
            EcdsaSha256,
            EcdsaSha384,
            EcdsaSha512,
        ] {
            if other != scheme {
                assert!(!x509::verify_signature(&key, other, tbs, sig), "{name} {other:?}");
            }
        }
    }
    // Signatures from rustls's signers, as a TLS server makes them.
    let msg = b"TLS 1.3, server CertificateVerify";
    for (scheme, ours) in [
        (SignatureScheme::RSA_PKCS1_SHA256, RsaPkcs1Sha256),
        (SignatureScheme::RSA_PKCS1_SHA384, RsaPkcs1Sha384),
        (SignatureScheme::RSA_PKCS1_SHA512, RsaPkcs1Sha512),
        (SignatureScheme::RSA_PSS_SHA256, RsaPssSha256),
        (SignatureScheme::RSA_PSS_SHA384, RsaPssSha384),
        (SignatureScheme::RSA_PSS_SHA512, RsaPssSha512),
    ] {
        for kind in [Kind::Rsa2048, Kind::Rsa3072, Kind::Rsa4096] {
            let sig = signer(kind, scheme).sign(msg).unwrap();
            let k = key(kind);
            let spki_der = rcgen::PublicKeyData::subject_public_key_info(&k);
            let spki = jpm_tls::der::Reader::new(&spki_der).expect(0x30).unwrap().to_vec();
            let key = public_key(&spki);
            assert!(x509::verify_signature(&key, ours, msg, &sig), "{scheme:?} {kind:?}");
            assert!(!x509::verify_signature(&key, ours, b"other", &sig), "{scheme:?} {kind:?}");
            assert!(!x509::verify_signature(&key, EcdsaSha256, msg, &sig));
        }
    }
    // EC keys with RSA schemes, and the other curve.
    let k = key(Kind::P256);
    let sig = rcgen::SigningKey::sign(&k, msg).unwrap();
    let p256 = PublicKey::P256(k.public_key_raw());
    assert!(x509::verify_signature(&p256, EcdsaSha256, msg, &sig));
    assert!(!x509::verify_signature(&p256, RsaPkcs1Sha256, msg, &sig));
    assert!(!x509::verify_signature(&PublicKey::P384(k.public_key_raw()), EcdsaSha256, msg, &sig));
    assert!(!x509::verify_signature(
        &PublicKey::Rsa { n: k.public_key_raw(), e: &[1, 0, 1] },
        RsaPkcs1Sha256,
        msg,
        &sig
    ));
}

/// The key in SubjectPublicKeyInfo contents, through verify_server on a self-issued leaf is
/// roundabout; build it the same way the parser does instead.
fn public_key(spki: &[u8]) -> PublicKey<'_> {
    let mut r = jpm_tls::der::Reader::new(spki);
    let alg = r.expect(0x30).unwrap();
    let bits = &r.expect(3).unwrap()[1..];
    if alg.starts_with(&hex_bytes("06092a864886f70d010101")) {
        let mut outer = jpm_tls::der::Reader::new(bits);
        let mut k = jpm_tls::der::Reader::new(outer.expect(0x30).unwrap());
        let n = k.expect(2).unwrap();
        let e = k.expect(2).unwrap();
        PublicKey::Rsa { n, e }
    } else if alg.ends_with(&hex_bytes("2a8648ce3d030107")) {
        PublicKey::P256(bits)
    } else {
        PublicKey::P384(bits)
    }
}

#[test]
fn loops_and_budgets() {
    // Two CAs that sign each other, and a leaf from one of them: no anchor, no endless search.
    let a = Node::root(ca_params("A"), Kind::P256);
    let b = Node::root(ca_params("B"), Kind::P256);
    let a_by_b = b.sign_key(ca_params("A"), key(Kind::P256));
    let b_by_a = a.sign_key(ca_params("B"), key(Kind::P256));
    let leaf = a.sign(leaf_params(&["example.com"]), Kind::P256);
    let root = Node::root(ca_params("root"), Kind::P256);
    let chain: Vec<&[u8]> = vec![&leaf.der, &a.der, &b.der, &a_by_b.der, &b_by_a.der];
    assert_eq!(check(&chain, "example.com", NOW, &[root.anchor()]), UNKNOWN);
    // Twelve CAs with one name, each signed by itself: the search is cut off by the step
    // budget, and it is quick.
    let cas: Vec<Node> = (0..12).map(|_| Node::root(ca_params("same"), Kind::P256)).collect();
    let leaf = cas[0].sign(leaf_params(&["example.com"]), Kind::P256);
    let mut chain: Vec<&[u8]> = vec![&leaf.der];
    chain.extend(cas.iter().map(|c| &c.der[..]));
    let start = std::time::Instant::now();
    let got = check(&chain, "example.com", NOW, &[root.anchor()]);
    assert!(got.is_err());
    eprintln!("12 same-name CAs, no anchor: {got:?} in {:?}", start.elapsed());
    // With an anchor of that name (and another key) every path ends in a signature check, and
    // the signature budget ends the search.
    let impostor = Node::root(ca_params("same"), Kind::P256);
    let start = std::time::Instant::now();
    let got = check(&chain, "example.com", NOW, &[impostor.anchor()]);
    eprintln!("12 same-name CAs, impostor anchor: {got:?} in {:?}", start.elapsed());
    assert!(got.is_err());
    // Each search step scans every certificate sent, so a chain is 64 certificates at most.
    let c = Chain::new(1, &["example.com"], &[Kind::P256]);
    let mut chain = c.ders();
    chain.resize(64, b"junk");
    assert_eq!(check(&chain, "example.com", NOW, &c.anchors()), Ok(()));
    chain.push(b"junk");
    assert_eq!(check(&chain, "example.com", NOW, &c.anchors()), Err("certificate path too complex"));
}
