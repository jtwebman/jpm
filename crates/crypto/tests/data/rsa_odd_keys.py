# RSA signatures for key shapes ring will not sign with and OpenSSL will not generate: odd
# sizes, e = 3, e = 2^32 - 1, the 8192-bit maximum, and 2047 / 8193 bits just outside the limits.
# Also SHA-1 signatures, which must fail, and for moduli of 8m+1 bits a PSS encoding behind a
# nonzero byte, which must fail too. Plain Python: random primes, pow() for the private
# operation, hashlib for the hashes. Run: python3 rsa_odd_keys.py rsa_odd_keys.json.gz
import gzip, hashlib, json, math, random, sys

rng = random.Random(20260928)
SMALL = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p ** 0.5) + 1, 2))]


def is_prime(n):
    if any(n % p == 0 for p in SMALL):
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for _ in range(12):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def prime(bits, e):
    while True:
        p = rng.getrandbits(bits) | (3 << (bits - 2)) | 1
        if math.gcd(e, p - 1) == 1 and is_prime(p):
            return p


def key(bits, e):
    while True:
        p = prime((bits + 1) // 2, e)
        q = prime(bits // 2, e)
        n = p * q
        if p != q and n.bit_length() == bits:
            return n, pow(e, -1, (p - 1) * (q - 1))


INFO = {
    "sha1": "3021300906052b0e03021a05000414",
    "sha256": "3031300d060960864801650304020105000420",
    "sha384": "3041300d060960864801650304020205000430",
    "sha512": "3051300d060960864801650304020305000440",
}


def mgf1(h, seed, length):
    out = b""
    for i in range((length + hashlib.new(h).digest_size - 1) // hashlib.new(h).digest_size):
        out += hashlib.new(h, seed + i.to_bytes(4, "big")).digest()
    return out[:length]


def encode(scheme, h, msg, mod_bits):
    m_hash = hashlib.new(h, msg).digest()
    h_len = len(m_hash)
    if scheme == "pkcs1":
        k = (mod_bits + 7) // 8
        t = bytes.fromhex(INFO[h]) + m_hash
        return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    em_bits = mod_bits - 1
    em_len = (em_bits + 7) // 8
    salt = rng.randbytes(h_len)
    hh = hashlib.new(h, b"\x00" * 8 + m_hash + salt).digest()
    db = b"\x00" * (em_len - 2 * h_len - 2) + b"\x01" + salt
    masked = bytearray(a ^ b for a, b in zip(db, mgf1(h, hh, len(db))))
    masked[0] &= 0xFF >> (8 * em_len - em_bits)
    return bytes(masked) + hh + b"\xbc"


shapes = [(2047, 65537), (2048, 3), (2049, 65537), (3071, 4294967295), (4097, 65537), (8192, 65537),
          (8193, 65537)]
vectors = []
for bits, e in shapes:
    n, d = key(bits, e)
    k = (bits + 7) // 8
    msg = f"jpm {bits}".encode()
    cases = [(scheme, h, "") for scheme in ("pkcs1", "pss") for h in ("sha1", "sha256", "sha384", "sha512")]
    if bits % 8 == 1:
        cases.append(("pss", "sha256", "nonzero first byte"))
    for scheme, h, note in cases:
        while True:
            m = int.from_bytes(encode(scheme, h, msg, bits), "big")
            if note:
                m += 1 << (bits - 1)
            if m < n:
                break
        s = pow(m, d, n)
        assert pow(s, e, n) == m
        vectors.append({"bits": bits, "n": n.to_bytes(k, "big").hex(), "e": e.to_bytes((e.bit_length() + 7) // 8, "big").hex(),
                        "scheme": scheme, "hash": h, "msg": msg.hex(), "sig": s.to_bytes(k, "big").hex(),
                        "valid": 2048 <= bits <= 8192 and h != "sha1" and not note, "note": note})
    print(bits, "done", file=sys.stderr)
with open(sys.argv[1], "wb") as f:
    f.write(gzip.compress(json.dumps(vectors, indent=0).encode(), 9, mtime=0))
print(len(vectors), "vectors")
