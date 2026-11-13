//! Cryptography for the key types, computed as Linux 6.12 computes it:
//!
//! - SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512, and HMAC over them;
//! - AES-128, AES-192 and AES-256 in CBC mode;
//! - modular exponentiation of big-endian integers;
//! - Diffie-Hellman and the SP800-56A KDF of `KEYCTL_DH_COMPUTE`;
//! - the `asymmetric` key type: X.509 certificates and PKCS#8 private keys
//!   holding RSA keys, their description, `KEYCTL_PKEY_QUERY`, the four
//!   public-key operations and the signature checks of keyring
//!   restrictions;
//! - the `encrypted` key type with a `user` master key.
//!
//! Errors are Linux errno values, positive.

use std::cmp::Ordering;

use fwe_abi::errno::{
    EBADMSG, EINVAL, EKEYREJECTED, EMSGSIZE, ENOENT, ENOKEY, ENOMEM, ENOPKG, ENOSYS, EOPNOTSUPP,
    EOVERFLOW,
};

// ---------------------------------------------------------------------------
// Hashes
// ---------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

#[derive(Clone)]
enum HashState {
    Sha1([u32; 5]),
    Sha256([u32; 8]),
    Sha512([u64; 8]),
}

/// A running hash of one of the supported algorithms.
#[derive(Clone)]
struct Hasher {
    state: HashState,
    out_len: usize,
    buf: [u8; 128],
    buf_len: usize,
    total: u128,
}

impl Hasher {
    fn new(name: &str) -> Option<Hasher> {
        let (state, out_len) = match name {
            "sha1" => {
                (HashState::Sha1([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]), 20)
            }
            "sha224" => (
                HashState::Sha256([
                    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511,
                    0x64f98fa7, 0xbefa4fa4,
                ]),
                28,
            ),
            "sha256" => (
                HashState::Sha256([
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                    0x1f83d9ab, 0x5be0cd19,
                ]),
                32,
            ),
            "sha384" => (
                HashState::Sha512([
                    0xcbbb9d5dc1059ed8,
                    0x629a292a367cd507,
                    0x9159015a3070dd17,
                    0x152fecd8f70e5939,
                    0x67332667ffc00b31,
                    0x8eb44a8768581511,
                    0xdb0c2e0d64f98fa7,
                    0x47b5481dbefa4fa4,
                ]),
                48,
            ),
            "sha512" => (
                HashState::Sha512([
                    0x6a09e667f3bcc908,
                    0xbb67ae8584caa73b,
                    0x3c6ef372fe94f82b,
                    0xa54ff53a5f1d36f1,
                    0x510e527fade682d1,
                    0x9b05688c2b3e6c1f,
                    0x1f83d9abfb41bd6b,
                    0x5be0cd19137e2179,
                ]),
                64,
            ),
            _ => return None,
        };
        Some(Hasher { state, out_len, buf: [0; 128], buf_len: 0, total: 0 })
    }

    fn block_size(&self) -> usize {
        match self.state {
            HashState::Sha512(_) => 128,
            _ => 64,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u128;
        let bs = self.block_size();
        if self.buf_len > 0 {
            let take = (bs - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == bs {
                let block = self.buf;
                self.compress(&block[..bs]);
                self.buf_len = 0;
            }
        }
        while data.len() >= bs {
            self.compress(&data[..bs]);
            data = &data[bs..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finish(mut self) -> Vec<u8> {
        let bs = self.block_size();
        let len_bytes = if bs == 128 { 16 } else { 8 };
        let bits = self.total.wrapping_mul(8);
        let mut pad = vec![0x80u8];
        let used = (self.buf_len + 1) % bs;
        let zeros = (2 * bs - len_bytes - used) % bs;
        pad.resize(1 + zeros, 0);
        if bs == 128 {
            pad.extend_from_slice(&bits.to_be_bytes());
        } else {
            pad.extend_from_slice(&(bits as u64).to_be_bytes());
        }
        self.update(&pad);
        let mut out = Vec::with_capacity(64);
        match self.state {
            HashState::Sha1(h) => h.iter().for_each(|w| out.extend_from_slice(&w.to_be_bytes())),
            HashState::Sha256(h) => h.iter().for_each(|w| out.extend_from_slice(&w.to_be_bytes())),
            HashState::Sha512(h) => h.iter().for_each(|w| out.extend_from_slice(&w.to_be_bytes())),
        }
        out.truncate(self.out_len);
        out
    }

    fn compress(&mut self, block: &[u8]) {
        match &mut self.state {
            HashState::Sha1(h) => sha1_compress(h, block),
            HashState::Sha256(h) => sha256_compress(h, block),
            HashState::Sha512(h) => sha512_compress(h, block),
        }
    }
}

fn sha1_compress(h: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];
    for (i, c) in block.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5a827999),
            20..=39 => (b ^ c ^ d, 0x6ed9eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
            _ => (b ^ c ^ d, 0xca62c1d6),
        };
        let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for (x, v) in h.iter_mut().zip([a, b, c, d, e]) {
        *x = x.wrapping_add(v);
    }
}

fn sha256_compress(h: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for (i, c) in block.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (x, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *x = x.wrapping_add(v);
    }
}

fn sha512_compress(h: &mut [u64; 8], block: &[u8]) {
    let mut w = [0u64; 80];
    for (i, c) in block.as_chunks::<8>().0.iter().enumerate() {
        w[i] = u64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA512_K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (x, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *x = x.wrapping_add(v);
    }
}

/// The digest size of hash `name`, or `None` if it is not supported.
pub fn hash_size(name: &str) -> Option<usize> {
    Hasher::new(name).map(|h| h.out_len)
}

/// Hashes the concatenation of `data` with "sha1", "sha224", "sha256",
/// "sha384" or "sha512"; `None` for any other name.
pub fn hash(name: &str, data: &[&[u8]]) -> Option<Vec<u8>> {
    let mut h = Hasher::new(name)?;
    data.iter().for_each(|d| h.update(d));
    Some(h.finish())
}

/// HMAC (RFC 2104) of the concatenation of `data` with key `key` over hash
/// `name`; `None` for an unsupported hash.
pub fn hmac(name: &str, key: &[u8], data: &[&[u8]]) -> Option<Vec<u8>> {
    let inner = Hasher::new(name)?;
    let bs = inner.block_size();
    let mut k = if key.len() > bs { hash(name, &[key])? } else { key.to_vec() };
    k.resize(bs, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut h = inner;
    h.update(&ipad);
    data.iter().for_each(|d| h.update(d));
    let ih = h.finish();
    hash(name, &[&opad, &ih])
}

// ---------------------------------------------------------------------------
// AES
// ---------------------------------------------------------------------------

const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

const fn make_sbox() -> [u8; 256] {
    let mut s = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        // The multiplicative inverse is x^254 in GF(2^8).
        let x = i as u8;
        let mut inv = 1u8;
        let mut base = x;
        let mut e = 254u32;
        while e != 0 {
            if e & 1 != 0 {
                inv = gf_mul(inv, base);
            }
            base = gf_mul(base, base);
            e >>= 1;
        }
        if x == 0 {
            inv = 0;
        }
        s[i] = inv
            ^ inv.rotate_left(1)
            ^ inv.rotate_left(2)
            ^ inv.rotate_left(3)
            ^ inv.rotate_left(4)
            ^ 0x63;
        i += 1;
    }
    s
}

const fn invert_sbox(s: &[u8; 256]) -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[s[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

const SBOX: [u8; 256] = make_sbox();
const INV_SBOX: [u8; 256] = invert_sbox(&SBOX);

/// An expanded AES key.
struct Aes {
    round_keys: Vec<[u8; 16]>,
}

impl Aes {
    fn new(key: &[u8]) -> Option<Aes> {
        let nk = match key.len() {
            16 => 4,
            24 => 6,
            32 => 8,
            _ => return None,
        };
        let nr = nk + 6;
        let total = 4 * (nr + 1);
        let mut w: Vec<[u8; 4]> =
            key.as_chunks::<4>().0.iter().map(|c| [c[0], c[1], c[2], c[3]]).collect();
        let mut rcon = 1u8;
        for i in nk..total {
            let mut t = w[i - 1];
            if i % nk == 0 {
                t = [
                    SBOX[t[1] as usize] ^ rcon,
                    SBOX[t[2] as usize],
                    SBOX[t[3] as usize],
                    SBOX[t[0] as usize],
                ];
                rcon = gf_mul(rcon, 2);
            } else if nk > 6 && i % nk == 4 {
                t = t.map(|b| SBOX[b as usize]);
            }
            let p = w[i - nk];
            w.push([p[0] ^ t[0], p[1] ^ t[1], p[2] ^ t[2], p[3] ^ t[3]]);
        }
        let round_keys = w
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| {
                let mut k = [0u8; 16];
                for (j, word) in c.iter().enumerate() {
                    k[4 * j..4 * j + 4].copy_from_slice(word);
                }
                k
            })
            .collect();
        Some(Aes { round_keys })
    }

    fn encrypt_block(&self, s: &mut [u8; 16]) {
        let nr = self.round_keys.len() - 1;
        xor16(s, &self.round_keys[0]);
        for (round, key) in self.round_keys.iter().enumerate().skip(1) {
            for b in s.iter_mut() {
                *b = SBOX[*b as usize];
            }
            let t = *s;
            for c in 0..4 {
                for r in 0..4 {
                    s[4 * c + r] = t[4 * ((c + r) % 4) + r];
                }
            }
            if round != nr {
                for c in 0..4 {
                    let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
                    for r in 0..4 {
                        s[4 * c + r] = gf_mul(a[r], 2)
                            ^ gf_mul(a[(r + 1) % 4], 3)
                            ^ a[(r + 2) % 4]
                            ^ a[(r + 3) % 4];
                    }
                }
            }
            xor16(s, key);
        }
    }

    fn decrypt_block(&self, s: &mut [u8; 16]) {
        let nr = self.round_keys.len() - 1;
        xor16(s, &self.round_keys[nr]);
        for round in (0..nr).rev() {
            let t = *s;
            for c in 0..4 {
                for r in 0..4 {
                    s[4 * ((c + r) % 4) + r] = t[4 * c + r];
                }
            }
            for b in s.iter_mut() {
                *b = INV_SBOX[*b as usize];
            }
            xor16(s, &self.round_keys[round]);
            if round != 0 {
                for c in 0..4 {
                    let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
                    for r in 0..4 {
                        s[4 * c + r] = gf_mul(a[r], 14)
                            ^ gf_mul(a[(r + 1) % 4], 11)
                            ^ gf_mul(a[(r + 2) % 4], 13)
                            ^ gf_mul(a[(r + 3) % 4], 9);
                    }
                }
            }
        }
    }
}

fn xor16(a: &mut [u8; 16], b: &[u8; 16]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

/// AES-CBC encryption with a 16, 24 or 32 byte key. `None` for another key
/// size or data that is not a whole number of 16-byte blocks.
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    if !data.len().is_multiple_of(16) {
        return None;
    }
    let aes = Aes::new(key)?;
    let mut prev = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.as_chunks::<16>().0.iter() {
        let mut b = [0u8; 16];
        b.copy_from_slice(chunk);
        xor16(&mut b, &prev);
        aes.encrypt_block(&mut b);
        out.extend_from_slice(&b);
        prev = b;
    }
    Some(out)
}

/// AES-CBC decryption, the inverse of [`aes_cbc_encrypt`].
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    if !data.len().is_multiple_of(16) {
        return None;
    }
    let aes = Aes::new(key)?;
    let mut prev = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.as_chunks::<16>().0.iter() {
        let mut b = [0u8; 16];
        b.copy_from_slice(chunk);
        let c = b;
        aes.decrypt_block(&mut b);
        xor16(&mut b, &prev);
        out.extend_from_slice(&b);
        prev = c;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Big integers: little-endian 64-bit limbs with no high zero limbs.
// ---------------------------------------------------------------------------

fn nat_norm(mut a: Vec<u64>) -> Vec<u64> {
    while a.last() == Some(&0) {
        a.pop();
    }
    a
}

fn nat_from_be(b: &[u8]) -> Vec<u64> {
    let mut out = Vec::with_capacity(b.len().div_ceil(8));
    for chunk in b.rchunks(8) {
        let mut w = [0u8; 8];
        w[8 - chunk.len()..].copy_from_slice(chunk);
        out.push(u64::from_be_bytes(w));
    }
    nat_norm(out)
}

/// The value as `len` big-endian bytes, dropping any higher bytes.
fn nat_to_be(a: &[u64], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for (i, limb) in a.iter().enumerate() {
        for (j, byte) in limb.to_le_bytes().iter().enumerate() {
            let pos = 8 * i + j;
            if pos < len {
                out[len - 1 - pos] = *byte;
            }
        }
    }
    out
}

/// The number of bytes of the value without leading zeros.
fn nat_bytes(a: &[u64]) -> usize {
    match a.last() {
        None => 0,
        Some(top) => 8 * (a.len() - 1) + (8 - top.leading_zeros() as usize / 8),
    }
}

fn nat_bits(a: &[u64]) -> usize {
    match a.last() {
        None => 0,
        Some(top) => 64 * a.len() - top.leading_zeros() as usize,
    }
}

fn nat_bit(a: &[u64], i: usize) -> bool {
    a.get(i / 64).is_some_and(|w| (w >> (i % 64)) & 1 == 1)
}

fn nat_cmp(a: &[u64], b: &[u64]) -> Ordering {
    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    for (x, y) in a.iter().rev().zip(b.iter().rev()) {
        if x != y {
            return x.cmp(y);
        }
    }
    Ordering::Equal
}

fn nat_small(v: u64) -> Vec<u64> {
    nat_norm(vec![v])
}

fn nat_add(a: &[u64], b: &[u64]) -> Vec<u64> {
    let (a, b) = if a.len() >= b.len() { (a, b) } else { (b, a) };
    let mut out = Vec::with_capacity(a.len() + 1);
    let mut carry = 0u64;
    for (i, &x) in a.iter().enumerate() {
        let y = b.get(i).copied().unwrap_or(0);
        let s = x as u128 + y as u128 + carry as u128;
        out.push(s as u64);
        carry = (s >> 64) as u64;
    }
    out.push(carry);
    nat_norm(out)
}

/// `a - b`, for `a >= b`.
fn nat_sub(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut out = Vec::with_capacity(a.len());
    let mut borrow = 0u64;
    for (i, &x) in a.iter().enumerate() {
        let y = b.get(i).copied().unwrap_or(0);
        let (d1, b1) = x.overflowing_sub(y);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out.push(d2);
        borrow = (b1 | b2) as u64;
    }
    nat_norm(out)
}

fn nat_mul(a: &[u64], b: &[u64]) -> Vec<u64> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut out = vec![0u64; a.len() + b.len()];
    for (i, &x) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, &y) in b.iter().enumerate() {
            let s = out[i + j] as u128 + x as u128 * y as u128 + carry as u128;
            out[i + j] = s as u64;
            carry = (s >> 64) as u64;
        }
        out[i + b.len()] = carry;
    }
    nat_norm(out)
}

fn nat_shl(a: &[u64], s: u32, extra: usize) -> Vec<u64> {
    let mut out = vec![0u64; a.len() + extra];
    for (i, &x) in a.iter().enumerate() {
        out[i] |= x << s;
        if s != 0 && i + 1 < out.len() {
            out[i + 1] |= x >> (64 - s);
        }
    }
    out
}

/// Quotient and remainder of `u / v` (Knuth, algorithm D), for `v != 0`.
fn nat_divrem(u: &[u64], v: &[u64]) -> (Vec<u64>, Vec<u64>) {
    assert!(!v.is_empty(), "division by zero");
    if nat_cmp(u, v) == Ordering::Less {
        return (Vec::new(), u.to_vec());
    }
    let n = v.len();
    if n == 1 {
        let d = v[0] as u128;
        let mut q = vec![0u64; u.len()];
        let mut r = 0u128;
        for i in (0..u.len()).rev() {
            let cur = (r << 64) | u[i] as u128;
            q[i] = (cur / d) as u64;
            r = cur % d;
        }
        return (nat_norm(q), nat_small(r as u64));
    }
    let m = u.len() - n;
    let s = v[n - 1].leading_zeros();
    let vn = nat_shl(v, s, 0);
    let mut un = nat_shl(u, s, 1);
    let mut q = vec![0u64; m + 1];
    let b: u128 = 1 << 64;
    let vtop = vn[n - 1] as u128;
    let vnext = vn[n - 2] as u128;
    for j in (0..=m).rev() {
        let num = ((un[j + n] as u128) << 64) | un[j + n - 1] as u128;
        let mut qhat = num / vtop;
        let mut rhat = num % vtop;
        while qhat >= b || qhat * vnext > ((rhat << 64) | un[j + n - 2] as u128) {
            qhat -= 1;
            rhat += vtop;
            if rhat >= b {
                break;
            }
        }
        let mut carry = 0u128;
        let mut borrow = 0u64;
        for i in 0..n {
            let p = qhat * vn[i] as u128 + carry;
            carry = p >> 64;
            let (t1, b1) = un[i + j].overflowing_sub(p as u64);
            let (t2, b2) = t1.overflowing_sub(borrow);
            un[i + j] = t2;
            borrow = b1 as u64 + b2 as u64;
        }
        let (t1, b1) = un[j + n].overflowing_sub(carry as u64);
        let (t2, b2) = t1.overflowing_sub(borrow);
        un[j + n] = t2;
        if b1 || b2 {
            qhat -= 1;
            let mut c = 0u128;
            for i in 0..n {
                let s2 = un[i + j] as u128 + vn[i] as u128 + c;
                un[i + j] = s2 as u64;
                c = s2 >> 64;
            }
            un[j + n] = un[j + n].wrapping_add(c as u64);
        }
        q[j] = qhat as u64;
    }
    let mut r = vec![0u64; n];
    for i in 0..n {
        r[i] = un[i] >> s;
        if s != 0 {
            r[i] |= un[i + 1] << (64 - s);
        }
    }
    (nat_norm(q), nat_norm(r))
}

fn nat_mod(a: &[u64], m: &[u64]) -> Vec<u64> {
    nat_divrem(a, m).1
}

/// Montgomery arithmetic modulo an odd `n`, with `R = 2^(64 * n.len())`.
struct Mont {
    n: Vec<u64>,
    n0inv: u64,
    r2: Vec<u64>,
}

impl Mont {
    fn new(n: &[u64]) -> Mont {
        let k = n.len();
        // -n^-1 mod 2^64 by Newton iteration.
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n[0].wrapping_mul(inv)));
        }
        let mut r2 = vec![0u64; 2 * k + 1];
        r2[2 * k] = 1;
        let mut r2 = nat_mod(&r2, n);
        r2.resize(k, 0);
        Mont { n: n.to_vec(), n0inv: inv.wrapping_neg(), r2 }
    }

    /// `out = a * b / R mod n`, for `a, b < n` of `n.len()` limbs; `t` is
    /// scratch of `n.len() + 2` limbs.
    fn mul(&self, out: &mut [u64], a: &[u64], b: &[u64], t: &mut [u64]) {
        let n = &self.n[..];
        let k = n.len();
        t.fill(0);
        for &bi in b {
            let mut c = 0u64;
            for (tj, &aj) in t.iter_mut().zip(a) {
                let s = *tj as u128 + aj as u128 * bi as u128 + c as u128;
                *tj = s as u64;
                c = (s >> 64) as u64;
            }
            let s = t[k] as u128 + c as u128;
            t[k] = s as u64;
            t[k + 1] = (s >> 64) as u64;
            // Add m * n, which makes the low limb zero, and drop that limb.
            let m = t[0].wrapping_mul(self.n0inv);
            let mut c = 0u64;
            for (tj, &nj) in t.iter_mut().zip(n) {
                let s = *tj as u128 + m as u128 * nj as u128 + c as u128;
                *tj = s as u64;
                c = (s >> 64) as u64;
            }
            let s = t[k] as u128 + c as u128;
            t[k] = s as u64;
            t[k + 1] += (s >> 64) as u64;
            t.copy_within(1..k + 2, 0);
            t[k + 1] = 0;
        }
        let ge = t[k] != 0 || {
            let mut ord = Ordering::Equal;
            for j in (0..k).rev() {
                if t[j] != n[j] {
                    ord = t[j].cmp(&n[j]);
                    break;
                }
            }
            ord != Ordering::Less
        };
        if ge {
            let mut borrow = 0u64;
            for j in 0..k {
                let (d1, b1) = t[j].overflowing_sub(n[j]);
                let (d2, b2) = d1.overflowing_sub(borrow);
                t[j] = d2;
                borrow = (b1 | b2) as u64;
            }
        }
        out.copy_from_slice(&t[..k]);
    }

    /// `base^exp mod n` for `base < n`.
    fn exp(&self, base: &[u64], exp: &[u64]) -> Vec<u64> {
        let k = self.n.len();
        let mut t = vec![0u64; k + 2];
        let mut b = base.to_vec();
        b.resize(k, 0);
        let mut one = vec![0u64; k];
        one[0] = 1;
        // Powers base^0 .. base^15 in Montgomery form.
        let mut table = vec![vec![0u64; k]; 16];
        self.mul(&mut table[0], &one, &self.r2, &mut t);
        let mut bm = vec![0u64; k];
        self.mul(&mut bm, &b, &self.r2, &mut t);
        table[1].copy_from_slice(&bm);
        for i in 2..16 {
            let (lo, hi) = table.split_at_mut(i);
            self.mul(&mut hi[0], &lo[i - 1], &bm, &mut t);
        }
        let mut acc = table[0].clone();
        let mut tmp = vec![0u64; k];
        let nibbles = nat_bits(exp).div_ceil(4);
        for i in (0..nibbles).rev() {
            for _ in 0..4 {
                self.mul(&mut tmp, &acc, &acc, &mut t);
                std::mem::swap(&mut acc, &mut tmp);
            }
            let limb = exp[i / 16];
            let nib = ((limb >> (4 * (i % 16))) & 0xf) as usize;
            if nib != 0 {
                self.mul(&mut tmp, &acc, &table[nib], &mut t);
                std::mem::swap(&mut acc, &mut tmp);
            }
        }
        self.mul(&mut tmp, &acc, &one, &mut t);
        nat_norm(tmp)
    }
}

/// `base^exp mod m` for `m != 0`.
fn nat_mod_exp(base: &[u64], exp: &[u64], m: &[u64]) -> Vec<u64> {
    if m == [1] {
        return Vec::new();
    }
    let b = nat_mod(base, m);
    if m[0] & 1 == 1 {
        return Mont::new(m).exp(&b, exp);
    }
    let mut acc = vec![1u64];
    for i in (0..nat_bits(exp)).rev() {
        acc = nat_mod(&nat_mul(&acc, &acc), m);
        if nat_bit(exp, i) {
            acc = nat_mod(&nat_mul(&acc, &b), m);
        }
    }
    acc
}

/// `base^exp mod modulus` of big-endian integers, as big-endian bytes of
/// the modulus's length without its leading zero bytes. `None` for a zero
/// modulus.
pub fn mod_exp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Option<Vec<u8>> {
    let m = nat_from_be(modulus);
    if m.is_empty() {
        return None;
    }
    let r = nat_mod_exp(&nat_from_be(base), &nat_from_be(exp), &m);
    Some(nat_to_be(&r, nat_bytes(&m)))
}

/// The size Linux gives an integer (`mpi_get_size`): its significant bytes
/// rounded up to whole 64-bit limbs.
fn mpi_size(a: &[u64]) -> usize {
    8 * a.len()
}

/// Linux reads integers of at most 16384 bits.
const MAX_MPI_BITS: usize = 16384;

fn strip_zeros(b: &[u8]) -> &[u8] {
    let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[i..]
}

// ---------------------------------------------------------------------------
// Diffie-Hellman
// ---------------------------------------------------------------------------

/// The most output `KEYCTL_DH_COMPUTE` derives with a KDF.
pub const KDF_MAX_OUTPUT_LEN: usize = 1024;
/// The most otherinfo `KEYCTL_DH_COMPUTE` takes with a KDF.
pub const KDF_MAX_OI_LEN: usize = 64;

/// Checks the payloads of the base, private and prime keys of
/// `KEYCTL_DH_COMPUTE` and gives the length of the shared secret: the
/// prime's significant bytes rounded up to 8. `EINVAL` for a prime shorter
/// than 1536 bits (counting its leading zero bytes), a base or private key
/// longer than the prime, a zero prime or a value over 16384 bits.
pub fn dh_secret_len(base: &[u8], private: &[u8], prime: &[u8]) -> Result<usize, i32> {
    if private.len() > prime.len() || base.len() > prime.len() {
        return Err(EINVAL);
    }
    if prime.iter().all(|&b| b == 0) {
        return Err(EINVAL);
    }
    if prime.len() * 8 < 1536 {
        return Err(EINVAL);
    }
    for v in [prime, base, private] {
        if strip_zeros(v).len() * 8 > MAX_MPI_BITS {
            return Err(EINVAL);
        }
    }
    Ok(strip_zeros(prime).len().div_ceil(8) * 8)
}

/// The shared secret `base^private mod prime` of `KEYCTL_DH_COMPUTE`,
/// zero-padded to [`dh_secret_len`] bytes, with its errors.
pub fn dh_compute(base: &[u8], private: &[u8], prime: &[u8]) -> Result<Vec<u8>, i32> {
    let len = dh_secret_len(base, private, prime)?;
    let r = nat_mod_exp(&nat_from_be(base), &nat_from_be(private), &nat_from_be(prime));
    Ok(nat_to_be(&r, len))
}

/// The SP800-56A KDF of `KEYCTL_DH_COMPUTE` (`crypto_kdf108_ctr_generate`
/// over a plain hash): the concatenation of `hash(counter || secret ||
/// otherinfo)` for a 32-bit big-endian counter from 1, cut to `out_len`.
/// `secret` is the zero-padded output of [`dh_compute`]. `None` for an
/// unsupported hash, for which Linux gives `ENOENT`.
pub fn dh_kdf(hashname: &str, secret: &[u8], otherinfo: &[u8], out_len: usize) -> Option<Vec<u8>> {
    hash_size(hashname)?;
    let mut out = Vec::with_capacity(out_len + 64);
    let mut counter = 1u32;
    while out.len() < out_len {
        out.extend(hash(hashname, &[&counter.to_be_bytes(), secret, otherinfo])?);
        counter = counter.wrapping_add(1);
    }
    out.truncate(out_len);
    Some(out)
}

// ---------------------------------------------------------------------------
// DER
// ---------------------------------------------------------------------------

const TAG_BOOL: u8 = 0x01;
const TAG_INT: u8 = 0x02;
const TAG_BITS: u8 = 0x03;
const TAG_OCTETS: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTCTIME: u8 = 0x17;
const TAG_GENTIME: u8 = 0x18;
const TAG_SEQ: u8 = 0x30;
const TAG_SET: u8 = 0x31;

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    whole: &'a [u8],
}

/// A reader of consecutive DER elements. Malformed data is `EBADMSG`.
struct Der<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Der<'a> {
    fn new(d: &'a [u8]) -> Der<'a> {
        Der { d, p: 0 }
    }

    fn done(&self) -> bool {
        self.p >= self.d.len()
    }

    fn peek(&self) -> Option<u8> {
        self.d.get(self.p).copied()
    }

    fn any(&mut self) -> Result<Tlv<'a>, i32> {
        let d = self.d;
        let start = self.p;
        if d.len() - start < 2 {
            return Err(EBADMSG);
        }
        let tag = d[start];
        if tag & 0x1f == 0x1f {
            return Err(EBADMSG);
        }
        let mut p = start + 2;
        let l0 = d[start + 1] as usize;
        let len = if l0 < 0x80 {
            l0
        } else {
            let n = l0 - 0x80;
            if n == 0 || n > 4 || d.len() - p < n {
                return Err(EBADMSG);
            }
            let v = d[p..p + n].iter().fold(0usize, |acc, &b| (acc << 8) | b as usize);
            p += n;
            v
        };
        if len > d.len() - p {
            return Err(EBADMSG);
        }
        self.p = p + len;
        Ok(Tlv { tag, value: &d[p..p + len], whole: &d[start..p + len] })
    }

    fn expect(&mut self, tag: u8) -> Result<Tlv<'a>, i32> {
        let t = self.any()?;
        if t.tag != tag {
            return Err(EBADMSG);
        }
        Ok(t)
    }

    fn optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>, i32> {
        if self.peek() == Some(tag) { Ok(Some(self.any()?)) } else { Ok(None) }
    }

    fn end(&self) -> Result<(), i32> {
        if self.done() { Ok(()) } else { Err(EBADMSG) }
    }
}

const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_O: &[u8] = &[0x55, 0x04, 0x0a];
const OID_EMAIL: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
const OID_SKID: &[u8] = &[0x55, 0x1d, 0x0e];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_AKID: &[u8] = &[0x55, 0x1d, 0x23];

/// The signature algorithm of an OID Linux knows: (public key algorithm,
/// hash).
fn sig_algo(oid: &[u8]) -> Option<(&'static str, &'static str)> {
    const PKCS1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
    const ECDSA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04];
    const NIST_SIG: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
    const GOST: &[u8] = &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x03];
    if let Some(rest) = oid.strip_prefix(PKCS1) {
        return match rest {
            [0x05] => Some(("rsa", "sha1")),
            [0x0b] => Some(("rsa", "sha256")),
            [0x0c] => Some(("rsa", "sha384")),
            [0x0d] => Some(("rsa", "sha512")),
            [0x0e] => Some(("rsa", "sha224")),
            _ => None,
        };
    }
    if let Some(rest) = oid.strip_prefix(ECDSA) {
        return match rest {
            [0x01] => Some(("ecdsa", "sha1")),
            [0x03, 0x01] => Some(("ecdsa", "sha224")),
            [0x03, 0x02] => Some(("ecdsa", "sha256")),
            [0x03, 0x03] => Some(("ecdsa", "sha384")),
            [0x03, 0x04] => Some(("ecdsa", "sha512")),
            _ => None,
        };
    }
    if let Some(rest) = oid.strip_prefix(NIST_SIG) {
        return match rest {
            [0x0a] => Some(("ecdsa", "sha3-256")),
            [0x0b] => Some(("ecdsa", "sha3-384")),
            [0x0c] => Some(("ecdsa", "sha3-512")),
            [0x0e] => Some(("rsa", "sha3-256")),
            [0x0f] => Some(("rsa", "sha3-384")),
            [0x10] => Some(("rsa", "sha3-512")),
            _ => None,
        };
    }
    if let Some(rest) = oid.strip_prefix(GOST) {
        return match rest {
            [0x02] => Some(("ecrdsa", "streebog256")),
            [0x03] => Some(("ecrdsa", "streebog512")),
            _ => None,
        };
    }
    None
}

/// An AlgorithmIdentifier: its OID.
fn parse_alg_id<'a>(t: &Tlv<'a>) -> Result<&'a [u8], i32> {
    let mut d = Der::new(t.value);
    let oid = d.expect(TAG_OID)?;
    if !d.done() {
        d.any()?;
    }
    d.end()?;
    Ok(oid.value)
}

/// The name Linux makes of a distinguished name (`x509_fabricate_name`)
/// from its last CN, O and emailAddress.
fn parse_name(value: &[u8]) -> Result<Vec<u8>, i32> {
    let mut cn: Option<&[u8]> = None;
    let mut o: Option<&[u8]> = None;
    let mut email: Option<&[u8]> = None;
    let mut rdns = Der::new(value);
    while !rdns.done() {
        let set = rdns.expect(TAG_SET)?;
        let mut avas = Der::new(set.value);
        while !avas.done() {
            let ava = avas.expect(TAG_SEQ)?;
            let mut a = Der::new(ava.value);
            let oid = a.expect(TAG_OID)?;
            let v = a.any()?;
            a.end()?;
            match oid.value {
                OID_CN => cn = Some(v.value),
                OID_O => o = Some(v.value),
                OID_EMAIL => email = Some(v.value),
                _ => {}
            }
        }
    }
    // Linux tracks each by its size, so an empty one counts as absent.
    let cn = cn.filter(|v| !v.is_empty());
    let o = o.filter(|v| !v.is_empty());
    let email = email.filter(|v| !v.is_empty());
    let name = match (cn, o) {
        (None, None) => email.unwrap_or(&[]).to_vec(),
        (Some(cn), Some(o)) => {
            if (cn.len() >= o.len() && cn.starts_with(o))
                || (cn.len() >= 7 && o.len() >= 7 && cn[..7] == o[..7])
            {
                cn.to_vec()
            } else {
                [o, b": ", cn].concat()
            }
        }
        (Some(cn), None) => cn.to_vec(),
        (None, Some(o)) => o.to_vec(),
    };
    Ok(name)
}

/// Validates an X.509 time as Linux's `x509_decode_time` does.
fn check_time(t: &Tlv) -> Result<(), i32> {
    let v = t.value;
    let digits = |s: &[u8]| -> Result<u32, i32> {
        s.iter().try_fold(0u32, |acc, &c| {
            if c.is_ascii_digit() { Ok(acc * 10 + (c - b'0') as u32) } else { Err(EBADMSG) }
        })
    };
    let (year, rest) = match t.tag {
        TAG_UTCTIME => {
            if v.len() != 13 {
                return Err(EBADMSG);
            }
            let y = digits(&v[..2])?;
            (if y >= 50 { y + 1900 } else { y + 2000 }, &v[2..])
        }
        TAG_GENTIME => {
            if v.len() != 15 {
                return Err(EBADMSG);
            }
            let y = digits(&v[..4])?;
            if (1950..=2049).contains(&y) {
                return Err(EBADMSG);
            }
            (y, &v[4..])
        }
        _ => return Err(EBADMSG),
    };
    let mon = digits(&rest[0..2])?;
    let day = digits(&rest[2..4])?;
    let hour = digits(&rest[4..6])?;
    let min = digits(&rest[6..8])?;
    let sec = digits(&rest[8..10])?;
    if rest[10] != b'Z' {
        return Err(EBADMSG);
    }
    if year < 1970 || !(1..=12).contains(&mon) {
        return Err(EBADMSG);
    }
    const MONTHS: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mon_len = MONTHS[mon as usize - 1];
    if mon == 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        mon_len = 29;
    }
    if day < 1 || day > mon_len || hour > 24 || min > 59 || sec > 60 {
        return Err(EBADMSG);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Asymmetric keys
// ---------------------------------------------------------------------------

/// An `asymmetric` key: an RSA public key from an X.509 certificate or an
/// RSA private key from PKCS#8, with what the certificate says about its
/// signature.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Asym {
    /// A PKCS#8 private key rather than a certificate.
    pub private: bool,
    /// The key size Linux reports, in bits; 0 if the key does not parse.
    pub key_bits: u32,
    /// The description Linux gives the key when `add_key` has none: the
    /// certificate's subject name, ": " and the hex of its subject key
    /// identifier or, without one, its serial number. Empty for PKCS#8,
    /// which has none (`add_key` then fails with `EINVAL`).
    pub description: Vec<u8>,
    /// The subject key identifier, or the serial number without one.
    pub fingerprint: Vec<u8>,
    /// The DER RSAPublicKey or RSAPrivateKey Linux keeps.
    pub key: Vec<u8>,
    /// The errno Linux gives when it uses a key it cannot load, else 0.
    pub key_error: i32,
    /// The RSA components, big-endian as encoded; empty when absent.
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub d: Vec<u8>,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub dp: Vec<u8>,
    pub dq: Vec<u8>,
    pub qinv: Vec<u8>,
    /// The DER TBSCertificate the signature covers.
    pub tbs: Vec<u8>,
    /// The signature's public-key algorithm ("rsa", "ecdsa", "ecrdsa").
    pub sig_pkey: String,
    /// The signature's hash; empty when the certificate has no signature
    /// Linux can check (none, or a hash it lacks).
    pub sig_hash: String,
    /// The signature.
    pub signature: Vec<u8>,
    /// The DER contents of the subject and issuer names.
    pub subject: Vec<u8>,
    pub issuer: Vec<u8>,
    /// The serial number as encoded.
    pub serial: Vec<u8>,
    /// The subject key identifier, empty when absent.
    pub skid: Vec<u8>,
    /// The authority key identifier's keyIdentifier.
    pub akid_keyid: Option<Vec<u8>>,
    /// The authority key identifier's serial number and the DER contents
    /// of its directoryName issuer, when it has both.
    pub akid_serial: Option<Vec<u8>>,
    pub akid_issuer: Option<Vec<u8>>,
}

/// A `KEYCTL_PKEY_QUERY` answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PkeyQuery {
    pub supported_ops: u32,
    pub key_size: u32,
    pub max_data_size: u16,
    pub max_sig_size: u16,
    pub max_enc_size: u16,
    pub max_dec_size: u16,
}

pub const KEYCTL_SUPPORTS_ENCRYPT: u32 = 0x01;
pub const KEYCTL_SUPPORTS_DECRYPT: u32 = 0x02;
pub const KEYCTL_SUPPORTS_SIGN: u32 = 0x04;
pub const KEYCTL_SUPPORTS_VERIFY: u32 = 0x08;

/// Parses an `asymmetric` key payload as Linux's parsers do, X.509 first,
/// then PKCS#8. `EINVAL` for an empty payload, `EBADMSG` when neither
/// parser recognises it, `EMSGSIZE` for a payload over 65535 bytes,
/// `ENOPKG` for an unsupported key or signature algorithm, `EINVAL` when
/// the two signature algorithms of a certificate differ and
/// `EKEYREJECTED` for a self-signed certificate whose signature does not
/// verify.
pub fn parse_asymmetric(data: &[u8]) -> Result<Asym, i32> {
    if data.is_empty() {
        return Err(EINVAL);
    }
    match parse_x509(data) {
        Err(EBADMSG) => parse_pkcs8(data),
        r => r,
    }
}

fn parse_x509(data: &[u8]) -> Result<Asym, i32> {
    if data.len() > 65535 {
        return Err(EMSGSIZE);
    }
    let mut a = Asym::default();
    let cert = Der::new(data).expect(TAG_SEQ)?;
    let mut c = Der::new(cert.value);
    let tbs = c.expect(TAG_SEQ)?;
    let mut t = Der::new(tbs.value);
    if let Some(v) = t.optional(0xa0)? {
        let mut vd = Der::new(v.value);
        vd.expect(TAG_INT)?;
        vd.end()?;
    }
    a.serial = t.expect(TAG_INT)?.value.to_vec();
    let inner_oid = parse_alg_id(&t.expect(TAG_SEQ)?)?;
    let (pkey, hash_name) = sig_algo(inner_oid).ok_or(ENOPKG)?;
    let issuer = t.expect(TAG_SEQ)?;
    a.issuer = issuer.value.to_vec();
    parse_name(issuer.value)?;
    let validity = t.expect(TAG_SEQ)?;
    let mut v = Der::new(validity.value);
    check_time(&v.any()?)?;
    check_time(&v.any()?)?;
    v.end()?;
    let subject = t.expect(TAG_SEQ)?;
    a.subject = subject.value.to_vec();
    let mut name = parse_name(subject.value)?;
    let spki = t.expect(TAG_SEQ)?;
    let mut s = Der::new(spki.value);
    let key_oid = parse_alg_id(&s.expect(TAG_SEQ)?)?;
    let bits = s.expect(TAG_BITS)?;
    s.end()?;
    if key_oid != OID_RSA {
        return Err(ENOPKG);
    }
    if bits.value.first() != Some(&0) {
        return Err(EBADMSG);
    }
    a.key = bits.value[1..].to_vec();
    for tag in [0x81, 0x82] {
        if t.peek().is_some_and(|x| x & !0x20 == tag) {
            t.any()?;
        }
    }
    let mut raw_akid: Option<&[u8]> = None;
    if let Some(ext) = t.optional(0xa3)? {
        let mut ed = Der::new(ext.value);
        let list = ed.expect(TAG_SEQ)?;
        ed.end()?;
        let mut l = Der::new(list.value);
        while !l.done() {
            let e = l.expect(TAG_SEQ)?;
            let mut x = Der::new(e.value);
            let oid = x.expect(TAG_OID)?.value;
            x.optional(TAG_BOOL)?;
            let v = x.expect(TAG_OCTETS)?.value;
            x.end()?;
            process_extension(&mut a, &mut raw_akid, oid, v)?;
        }
    }
    t.end()?;
    let outer_oid = parse_alg_id(&c.expect(TAG_SEQ)?)?;
    let sig = c.expect(TAG_BITS)?;
    c.end()?;
    if outer_oid != inner_oid {
        return Err(EINVAL);
    }
    if sig.value.first() != Some(&0) {
        return Err(EBADMSG);
    }
    a.signature = sig.value[1..].to_vec();
    a.tbs = tbs.whole.to_vec();
    a.sig_pkey = pkey.to_string();
    if let Some(akid) = raw_akid {
        parse_akid(&mut a, akid)?;
    }
    if hash_size(hash_name).is_some() {
        a.sig_hash = hash_name.to_string();
    }
    load_rsa_key(&mut a);
    check_self_signed(&a)?;
    // The description stops at a NUL in the subject name, as a C string.
    if let Some(i) = name.iter().position(|&b| b == 0) {
        name.truncate(i);
    }
    a.fingerprint = if a.skid.is_empty() { a.serial.clone() } else { a.skid.clone() };
    a.description = [name.as_slice(), b": ", hex(&a.fingerprint).as_bytes()].concat();
    Ok(a)
}

fn process_extension<'a>(
    a: &mut Asym,
    raw_akid: &mut Option<&'a [u8]>,
    oid: &[u8],
    v: &'a [u8],
) -> Result<(), i32> {
    let bad = match oid {
        OID_SKID => {
            let bad = !a.skid.is_empty()
                || v.len() < 3
                || v[0] != TAG_OCTETS
                || v[1] as usize != v.len() - 2;
            if !bad {
                a.skid = v[2..].to_vec();
            }
            bad
        }
        OID_KEY_USAGE => v.len() < 4 || v[0] != TAG_BITS || v[2] >= 8,
        OID_AKID => {
            *raw_akid = Some(v);
            false
        }
        OID_BASIC_CONSTRAINTS => v.len() < 2 || v[0] != TAG_SEQ || v[1] as usize != v.len() - 2,
        _ => false,
    };
    if bad { Err(EBADMSG) } else { Ok(()) }
}

/// Decodes an AuthorityKeyIdentifier extension.
fn parse_akid(a: &mut Asym, data: &[u8]) -> Result<(), i32> {
    let seq = Der::new(data).expect(TAG_SEQ)?;
    let mut d = Der::new(seq.value);
    if let Some(kid) = d.optional(0x80)? {
        a.akid_keyid = Some(kid.value.to_vec());
    }
    let mut issuer: Option<&[u8]> = None;
    if let Some(names) = d.optional(0xa1)? {
        let mut g = Der::new(names.value);
        while !g.done() {
            let n = g.any()?;
            if n.tag & 0xc0 != 0x80 || n.tag & 0x1f > 8 {
                return Err(EBADMSG);
            }
            if n.tag == 0xa4 {
                let mut inner = Der::new(n.value);
                let name = inner.expect(TAG_SEQ)?;
                inner.end()?;
                parse_name(name.value)?;
                issuer = Some(name.value);
            }
        }
    }
    if let Some(serial) = d.optional(0x82)?
        && let Some(issuer) = issuer
    {
        a.akid_serial = Some(serial.value.to_vec());
        a.akid_issuer = Some(issuer.to_vec());
    }
    d.end()
}

/// Linux's `x509_check_for_self_signed`.
fn check_self_signed(a: &Asym) -> Result<(), i32> {
    if a.subject != a.issuer {
        return Ok(());
    }
    let [auth0, auth1, _] = auth_ids(a);
    if auth0.is_some() || auth1.is_some() {
        let [id0, id1, _] = key_ids(a);
        let m1 = same_id(&id1, &auth1);
        let m0 = same_id(&id0, &auth0);
        if !m1 && !m0 {
            return Ok(());
        }
        if m1 != m0 && auth0.is_some() && auth1.is_some() {
            return Err(EKEYREJECTED);
        }
    }
    if a.sig_hash.is_empty() {
        return Ok(());
    }
    match verify_cert_signature(a, a) {
        Err(ENOPKG) => Ok(()),
        r => r,
    }
}

fn parse_pkcs8(data: &[u8]) -> Result<Asym, i32> {
    if data.len() > 65535 {
        return Err(EMSGSIZE);
    }
    let seq = Der::new(data).expect(TAG_SEQ)?;
    let mut d = Der::new(seq.value);
    let version = d.expect(TAG_INT)?;
    if version.value != [0] {
        return Err(EBADMSG);
    }
    let oid = parse_alg_id(&d.expect(TAG_SEQ)?)?;
    if oid != OID_RSA {
        return Err(ENOPKG);
    }
    let key = d.expect(TAG_OCTETS)?;
    d.optional(0xa0)?;
    d.end()?;
    let mut a = Asym { private: true, key: key.value.to_vec(), ..Asym::default() };
    load_rsa_key(&mut a);
    Ok(a)
}

/// Decodes the RSA key in `a.key` as Linux's `rsa_parse_pub_key` or
/// `rsa_parse_priv_key` and `rsa_set_*_key` do, recording the components,
/// the key size and the errno a use of the key gives.
fn load_rsa_key(a: &mut Asym) {
    match decode_rsa(&a.key, a.private) {
        Ok(parts) => {
            [a.n, a.e, a.d, a.p, a.q, a.dp, a.dq, a.qinv] = parts;
            let n = strip_zeros(&a.n);
            if n.len() * 8 > MAX_MPI_BITS
                || [&a.e, &a.d, &a.p, &a.q, &a.dp, &a.dq, &a.qinv]
                    .iter()
                    .any(|v| strip_zeros(v).len() * 8 > MAX_MPI_BITS)
            {
                a.key_error = ENOMEM;
                return;
            }
            let ksz = n.len().div_ceil(8) * 8;
            a.key_bits = (ksz * 8) as u32;
            if !matches!(ksz * 8, 512 | 1024 | 1536 | 2048 | 3072 | 4096) {
                a.key_error = EINVAL;
            }
        }
        Err(e) => a.key_error = e,
    }
}

fn decode_rsa(key: &[u8], private: bool) -> Result<[Vec<u8>; 8], i32> {
    let seq = Der::new(key).expect(TAG_SEQ)?;
    let mut d = Der::new(seq.value);
    let mut parts: [Vec<u8>; 8] = Default::default();
    if private {
        d.expect(TAG_INT)?;
    }
    let count = if private { 8 } else { 2 };
    let mut n_len = 0;
    for (i, part) in parts.iter_mut().enumerate().take(count) {
        let v = d.expect(TAG_INT)?.value;
        if v.is_empty() || (i > 0 && v.len() > n_len) {
            return Err(EINVAL);
        }
        if i == 0 {
            n_len = v.len();
        }
        *part = v.to_vec();
    }
    d.end()?;
    Ok(parts)
}

/// The identifiers Linux gives a key from a certificate: issuer and serial
/// number, subject key identifier, and subject name.
fn key_ids(a: &Asym) -> [Option<Vec<u8>>; 3] {
    if a.private {
        return [None, None, None];
    }
    [
        Some([a.serial.as_slice(), a.issuer.as_slice()].concat()),
        (!a.skid.is_empty()).then(|| a.skid.clone()),
        Some(a.subject.clone()),
    ]
}

/// The identifiers of the key that signed a certificate: authority serial
/// number and issuer, authority key identifier, and issuer name.
fn auth_ids(a: &Asym) -> [Option<Vec<u8>>; 3] {
    if a.private {
        return [None, None, None];
    }
    let id0 = match (&a.akid_serial, &a.akid_issuer) {
        (Some(s), Some(i)) => Some([s.as_slice(), i.as_slice()].concat()),
        _ => None,
    };
    [id0, a.akid_keyid.clone(), Some(a.issuer.clone())]
}

fn same_id(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> bool {
    matches!((a, b), (Some(x), Some(y)) if x == y)
}

/// Checks that a key can be used for a restriction's signature check:
/// `ENOPKG` when `subject` has no signature Linux can check (a PKCS#8 key,
/// or a hash it lacks).
pub fn signature_precheck(subject: &Asym) -> Result<(), i32> {
    if subject.private || subject.sig_hash.is_empty() {
        return Err(ENOPKG);
    }
    Ok(())
}

/// Whether `candidate` is the key a keyring search for `subject`'s signer
/// finds (`find_asymmetric_key`, exact match): its issuer-and-serial or
/// subject key identifier matches the authority identifier `subject`
/// prefers, or, when `subject` has neither, its subject name matches
/// `subject`'s issuer.
pub fn keyring_signer_matches(subject: &Asym, candidate: &Asym) -> bool {
    let [a0, a1, a2] = auth_ids(subject);
    let ids = key_ids(candidate);
    match a0.or(a1) {
        Some(id) => {
            let id = Some(id);
            same_id(&ids[0], &id) || same_id(&ids[1], &id)
        }
        None => same_id(&ids[2], &a2),
    }
}

/// Whether the key a keyring search found for `subject`'s signer is kept:
/// when `subject` names both an issuer-and-serial and a key identifier,
/// the key's subject key identifier must match the latter. Linux gives
/// `ENOKEY` when it is not.
pub fn keyring_signer_accepted(subject: &Asym, found: &Asym) -> bool {
    let [a0, a1, _] = auth_ids(subject);
    if a0.is_some() && a1.is_some() {
        return same_id(&key_ids(found)[1], &a1);
    }
    true
}

/// Whether certificate `subject` is signed by `signer`'s key, as the
/// `key_or_keyring` restriction checks it against one key: `ENOPKG` when
/// `subject` has no checkable signature, `ENOKEY` when `signer` is not the
/// key `subject`'s authority identifiers name, `EKEYREJECTED` (or
/// `EBADMSG`) for a signature that does not verify, and `EINVAL` when the
/// signature or key does not fit.
pub fn verify_signed_by(subject: &Asym, signer: &Asym) -> Result<(), i32> {
    signature_precheck(subject)?;
    let [a0, a1, a2] = auth_ids(subject);
    let ids = key_ids(signer);
    if signer.private {
        return Err(ENOKEY);
    }
    let either = |id: &Option<Vec<u8>>| same_id(&ids[0], id) || same_id(&ids[1], id);
    let matched = match (&a0, &a1) {
        (None, None) => same_id(&ids[2], &a2),
        (Some(_), None) => either(&a0),
        (None, Some(_)) => either(&a1),
        (Some(_), Some(_)) => same_id(&ids[1], &a1) && either(&a0),
    };
    if !matched {
        return Err(ENOKEY);
    }
    verify_cert_signature(subject, signer)
}

/// Verifies `subject`'s certificate signature with `signer`'s key
/// (`public_key_verify_signature`).
pub fn verify_cert_signature(subject: &Asym, signer: &Asym) -> Result<(), i32> {
    signature_precheck(subject)?;
    if subject.sig_pkey != "rsa" {
        return Err(EKEYREJECTED);
    }
    let info = pkcs1_digest_info(&subject.sig_hash).ok_or(ENOENT)?;
    let rsa = RsaKey::new(signer)?;
    let digest = hash(&subject.sig_hash, &[&subject.tbs]).ok_or(ENOPKG)?;
    pkcs1_verify(&rsa, Some(info), &subject.signature, &digest)
}

impl Asym {
    /// Serialises the key for storage.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.private as u8];
        out.extend_from_slice(&self.key_bits.to_le_bytes());
        out.extend_from_slice(&self.key_error.to_le_bytes());
        for f in self.byte_fields() {
            put_bytes(&mut out, f);
        }
        put_bytes(&mut out, self.sig_pkey.as_bytes());
        put_bytes(&mut out, self.sig_hash.as_bytes());
        for f in [&self.akid_keyid, &self.akid_serial, &self.akid_issuer] {
            match f {
                None => out.push(0),
                Some(v) => {
                    out.push(1);
                    put_bytes(&mut out, v);
                }
            }
        }
        out
    }

    /// The inverse of [`Asym::encode`]; `None` for malformed data.
    pub fn decode(data: &[u8]) -> Option<Asym> {
        let mut r = data;
        let mut a = Asym {
            private: match take(&mut r, 1)? {
                [0] => false,
                [1] => true,
                _ => return None,
            },
            key_bits: u32::from_le_bytes(take(&mut r, 4)?.try_into().ok()?),
            key_error: i32::from_le_bytes(take(&mut r, 4)?.try_into().ok()?),
            ..Asym::default()
        };
        for f in a.byte_fields_mut() {
            *f = get_bytes(&mut r)?;
        }
        a.sig_pkey = String::from_utf8(get_bytes(&mut r)?).ok()?;
        a.sig_hash = String::from_utf8(get_bytes(&mut r)?).ok()?;
        for f in [&mut a.akid_keyid, &mut a.akid_serial, &mut a.akid_issuer] {
            *f = match take(&mut r, 1)? {
                [0] => None,
                [1] => Some(get_bytes(&mut r)?),
                _ => return None,
            };
        }
        r.is_empty().then_some(a)
    }

    fn byte_fields(&self) -> [&Vec<u8>; 17] {
        [
            &self.description,
            &self.fingerprint,
            &self.key,
            &self.n,
            &self.e,
            &self.d,
            &self.p,
            &self.q,
            &self.dp,
            &self.dq,
            &self.qinv,
            &self.tbs,
            &self.signature,
            &self.subject,
            &self.issuer,
            &self.serial,
            &self.skid,
        ]
    }

    fn byte_fields_mut(&mut self) -> [&mut Vec<u8>; 17] {
        [
            &mut self.description,
            &mut self.fingerprint,
            &mut self.key,
            &mut self.n,
            &mut self.e,
            &mut self.d,
            &mut self.p,
            &mut self.q,
            &mut self.dp,
            &mut self.dq,
            &mut self.qinv,
            &mut self.tbs,
            &mut self.signature,
            &mut self.subject,
            &mut self.issuer,
            &mut self.serial,
            &mut self.skid,
        ]
    }
}

fn put_bytes(out: &mut Vec<u8>, v: &[u8]) {
    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    out.extend_from_slice(v);
}

fn take<'a>(r: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if r.len() < n {
        return None;
    }
    let (head, tail) = r.split_at(n);
    *r = tail;
    Some(head)
}

fn get_bytes(r: &mut &[u8]) -> Option<Vec<u8>> {
    let len = u32::from_le_bytes(take(r, 4)?.try_into().ok()?) as usize;
    Some(take(r, len)?.to_vec())
}

// --- RSA ---

/// A loaded RSA key, as `rsa_set_pub_key` or `rsa_set_priv_key` leave it.
struct RsaKey {
    n: Vec<u64>,
    e: Vec<u64>,
    private: Option<RsaPrivate>,
    /// The modulus size in bytes as Linux counts it (`mpi_get_size`).
    size: usize,
}

struct RsaPrivate {
    p: Vec<u64>,
    q: Vec<u64>,
    dp: Vec<u64>,
    dq: Vec<u64>,
    qinv: Vec<u64>,
}

impl RsaKey {
    fn new(a: &Asym) -> Result<RsaKey, i32> {
        if a.key_error != 0 {
            return Err(a.key_error);
        }
        let n = nat_from_be(&a.n);
        let private = a.private.then(|| RsaPrivate {
            p: nat_from_be(&a.p),
            q: nat_from_be(&a.q),
            dp: nat_from_be(&a.dp),
            dq: nat_from_be(&a.dq),
            qinv: nat_from_be(&a.qinv),
        });
        Ok(RsaKey { size: mpi_size(&n), e: nat_from_be(&a.e), n, private })
    }

    /// `rsa_check_payload`: 1 < x < n - 1.
    fn check_payload(&self, x: &[u64]) -> Result<(), i32> {
        if nat_cmp(x, &[1]) != Ordering::Greater
            || nat_cmp(x, &nat_sub(&self.n, &[1])) != Ordering::Less
        {
            return Err(EINVAL);
        }
        Ok(())
    }

    /// RSAEP into `out_len` bytes (`rsa_enc`).
    fn encrypt(&self, m: &[u8], out_len: usize) -> Result<Vec<u8>, i32> {
        let m = nat_from_be(m);
        self.check_payload(&m)?;
        let c = nat_mod_exp(&m, &self.e, &self.n);
        if mpi_size(&c) > out_len {
            return Err(EOVERFLOW);
        }
        Ok(nat_to_be(&c, out_len))
    }

    /// RSADP by the Chinese remainder theorem into `out_len` bytes
    /// (`rsa_dec`); `EINVAL` for a public key.
    fn decrypt(&self, c: &[u8], out_len: usize) -> Result<Vec<u8>, i32> {
        let k = self.private.as_ref().ok_or(EINVAL)?;
        let c = nat_from_be(c);
        self.check_payload(&c)?;
        if k.p.is_empty() || k.q.is_empty() {
            return Err(EINVAL);
        }
        let m1 = nat_mod_exp(&c, &k.dp, &k.p);
        let m2 = nat_mod_exp(&c, &k.dq, &k.q);
        let m2p = nat_mod(&m2, &k.p);
        let diff = if nat_cmp(&m1, &m2p) == Ordering::Less {
            nat_sub(&nat_add(&m1, &k.p), &m2p)
        } else {
            nat_sub(&m1, &m2p)
        };
        let h = nat_mod(&nat_mul(&diff, &k.qinv), &k.p);
        let m = nat_mod(&nat_add(&m2, &nat_mul(&k.q, &h)), &self.n);
        if mpi_size(&m) > out_len {
            return Err(EOVERFLOW);
        }
        Ok(nat_to_be(&m, out_len))
    }
}

/// The DER DigestInfo prefixes of `pkcs1pad(rsa,<hash>)`.
fn pkcs1_digest_info(hash: &str) -> Option<&'static [u8]> {
    Some(match hash {
        "md5" => &[
            0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
            0x05, 0x00, 0x04, 0x10,
        ],
        "sha1" => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ],
        "rmd160" => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04,
            0x14,
        ],
        "sha224" => &[
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x04, 0x05, 0x00, 0x04, 0x1c,
        ],
        "sha256" => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        "sha384" => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        "sha512" => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
        "sha3-256" => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x08, 0x05, 0x00, 0x04, 0x20,
        ],
        "sha3-384" => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x09, 0x05, 0x00, 0x04, 0x30,
        ],
        "sha3-512" => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x0a, 0x05, 0x00, 0x04, 0x40,
        ],
        _ => return None,
    })
}

/// `pkcs1pad` verification of `sig` over `digest`.
fn pkcs1_verify(rsa: &RsaKey, info: Option<&[u8]>, sig: &[u8], digest: &[u8]) -> Result<(), i32> {
    let ks = rsa.size;
    if digest.is_empty() || sig.len() != ks {
        return Err(EINVAL);
    }
    let out = rsa.encrypt(sig, ks)?;
    if out[0] != 0 {
        return Err(EINVAL);
    }
    let out = &out[1..];
    if out[0] != 0x01 {
        return Err(EBADMSG);
    }
    let mut pos = 1;
    while pos < out.len() && out[pos] == 0xff {
        pos += 1;
    }
    if pos < 9 || pos == out.len() || out[pos] != 0 {
        return Err(EBADMSG);
    }
    pos += 1;
    if let Some(info) = info {
        if info.len() > out.len() - pos || out[pos..pos + info.len()] != *info {
            return Err(EBADMSG);
        }
        pos += info.len();
    }
    if digest.len() != out.len() - pos || out[pos..] != *digest {
        return Err(EKEYREJECTED);
    }
    Ok(())
}

/// The parameters of a public-key operation's info string.
struct PkeyParams<'a> {
    encoding: &'a str,
    hash: Option<&'a str>,
}

/// Parses "enc=<encoding> hash=<hash>" (`keyctl_pkey_params_parse`): the
/// encoding defaults to "raw"; an unknown, repeated or empty option is
/// `EINVAL`.
fn parse_info(info: &str) -> Result<PkeyParams<'_>, i32> {
    let mut encoding = None;
    let mut hash = None;
    for tok in info.split([' ', '\t']).filter(|t| !t.is_empty()) {
        let (slot, v) = if let Some(v) = tok.strip_prefix("enc=") {
            (&mut encoding, v)
        } else if let Some(v) = tok.strip_prefix("hash=") {
            (&mut hash, v)
        } else {
            return Err(EINVAL);
        };
        if slot.is_some() || v.is_empty() {
            return Err(EINVAL);
        }
        *slot = Some(v);
    }
    Ok(PkeyParams { encoding: encoding.unwrap_or("raw"), hash })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PkeyOp {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
}

/// The RSA algorithm of an operation.
#[derive(Clone, Copy)]
enum RsaAlg {
    Raw,
    /// `pkcs1pad`, with the DigestInfo of its hash if one is named.
    Pkcs1(Option<&'static [u8]>),
}

/// The algorithm an operation uses (`software_key_determine_akcipher` and
/// the crypto API lookup that follows) and whether it is a signature
/// algorithm.
fn determine(p: &PkeyParams, op: PkeyOp) -> Result<(RsaAlg, bool), i32> {
    if p.encoding == "pkcs1" {
        let issig = matches!(op, PkeyOp::Sign | PkeyOp::Verify);
        let info = match p.hash {
            None => None,
            Some(h) => Some(pkcs1_digest_info(h).ok_or(ENOENT)?),
        };
        return Ok((RsaAlg::Pkcs1(info), issig));
    }
    if p.encoding != "raw" || p.hash.is_some() {
        return Err(EINVAL);
    }
    Ok((RsaAlg::Raw, false))
}

/// `KEYCTL_PKEY_QUERY` with info string `info`.
pub fn pkey_query(key: &Asym, info: &str) -> Result<PkeyQuery, i32> {
    query_params(key, &parse_info(info)?)
}

fn query_params(key: &Asym, p: &PkeyParams) -> Result<PkeyQuery, i32> {
    let (_, issig) = determine(p, PkeyOp::Sign)?;
    let rsa = RsaKey::new(key)?;
    let len = rsa.size;
    let mut ops = KEYCTL_SUPPORTS_ENCRYPT;
    if key.private {
        ops |= KEYCTL_SUPPORTS_DECRYPT;
    }
    if issig {
        ops |= KEYCTL_SUPPORTS_VERIFY;
        if key.private {
            ops |= KEYCTL_SUPPORTS_SIGN;
        }
    }
    Ok(PkeyQuery {
        supported_ops: ops,
        key_size: (len * 8) as u32,
        max_data_size: len as u16,
        max_sig_size: len as u16,
        max_enc_size: len as u16,
        max_dec_size: len as u16,
    })
}

/// The size checks of `keyctl_pkey_params_get_2`.
fn check_sizes(q: &PkeyQuery, op: PkeyOp, in_len: usize, out_len: usize) -> Result<(), i32> {
    let (max_in, max_out) = match op {
        PkeyOp::Encrypt => (q.max_dec_size, q.max_enc_size),
        PkeyOp::Decrypt => (q.max_enc_size, q.max_dec_size),
        PkeyOp::Sign => (q.max_data_size, q.max_sig_size),
        PkeyOp::Verify => (q.max_data_size, q.max_sig_size),
    };
    if in_len > max_in as usize || out_len > max_out as usize {
        return Err(EINVAL);
    }
    Ok(())
}

/// `KEYCTL_PKEY_ENCRYPT`, `DECRYPT` or `SIGN` (`software_key_eds_op`):
/// the bytes Linux returns, as many as its result.
fn eds(
    key: &Asym,
    info: &str,
    op: PkeyOp,
    input: &[u8],
    out_len: usize,
    random: &mut dyn FnMut(&mut [u8]),
) -> Result<Vec<u8>, i32> {
    let p = parse_info(info)?;
    let q = query_params(key, &p)?;
    check_sizes(&q, op, input.len(), out_len)?;
    let (alg, issig) = determine(&p, op)?;
    let rsa = RsaKey::new(key)?;
    let ksz = rsa.size;
    let (mut out, ret) = match (op, alg) {
        (PkeyOp::Encrypt, _) | (PkeyOp::Decrypt, _) if issig => return Err(EINVAL),
        (PkeyOp::Sign, _) if !issig => return Err(EINVAL),
        (PkeyOp::Encrypt, RsaAlg::Raw) => (rsa.encrypt(input, out_len)?, ksz),
        (PkeyOp::Decrypt, RsaAlg::Raw) => (rsa.decrypt(input, out_len)?, out_len),
        (PkeyOp::Encrypt, RsaAlg::Pkcs1(_)) => {
            if input.len() + 11 > ksz || out_len < ksz {
                return Err(EOVERFLOW);
            }
            let ps_end = ksz - input.len() - 2;
            let mut m = vec![0u8; ksz - 1];
            m[0] = 0x02;
            random(&mut m[1..ps_end]);
            for b in &mut m[1..ps_end] {
                while *b == 0 {
                    let mut one = [0u8; 1];
                    random(&mut one);
                    *b = one[0];
                }
            }
            m[ps_end] = 0;
            m[ps_end + 1..].copy_from_slice(input);
            (rsa.encrypt(&m, out_len)?, ksz)
        }
        (PkeyOp::Decrypt, RsaAlg::Pkcs1(_)) => {
            if input.len() != ksz {
                return Err(EINVAL);
            }
            let m = rsa.decrypt(input, ksz)?;
            if m[0] != 0 || m[1] != 0x02 {
                return Err(EINVAL);
            }
            let m = &m[1..];
            let pos = (1..m.len()).find(|&i| m[i] == 0).ok_or(EINVAL)?;
            if pos < 9 {
                return Err(EINVAL);
            }
            let plain = &m[pos + 1..];
            if out_len < plain.len() {
                return Err(EOVERFLOW);
            }
            (plain.to_vec(), plain.len())
        }
        (PkeyOp::Sign, RsaAlg::Pkcs1(info)) => {
            let info = info.unwrap_or(&[]);
            if input.len() + info.len() + 11 > ksz || out_len < ksz {
                return Err(EOVERFLOW);
            }
            let ps_end = ksz - info.len() - input.len() - 2;
            let mut m = vec![0xffu8; ksz - 1];
            m[0] = 0x01;
            m[ps_end] = 0;
            m[ps_end + 1..ps_end + 1 + info.len()].copy_from_slice(info);
            m[ps_end + 1 + info.len()..].copy_from_slice(input);
            (rsa.decrypt(&m, out_len)?, ksz)
        }
        _ => return Err(EINVAL),
    };
    out.resize(ret, 0);
    Ok(out)
}

/// `KEYCTL_PKEY_ENCRYPT` of `input` into a buffer of `out_len` bytes; the
/// result's length is what Linux returns. PKCS#1 padding takes its random
/// bytes from `random`.
pub fn pkey_encrypt(
    key: &Asym,
    info: &str,
    input: &[u8],
    out_len: usize,
    random: &mut dyn FnMut(&mut [u8]),
) -> Result<Vec<u8>, i32> {
    eds(key, info, PkeyOp::Encrypt, input, out_len, random)
}

/// `KEYCTL_PKEY_DECRYPT`; `EINVAL` with a public key, as Linux gives.
pub fn pkey_decrypt(key: &Asym, info: &str, input: &[u8], out_len: usize) -> Result<Vec<u8>, i32> {
    eds(key, info, PkeyOp::Decrypt, input, out_len, &mut |_| {})
}

/// `KEYCTL_PKEY_SIGN`; `EINVAL` with a public key or "enc=raw", as Linux
/// gives.
pub fn pkey_sign(key: &Asym, info: &str, input: &[u8], out_len: usize) -> Result<Vec<u8>, i32> {
    eds(key, info, PkeyOp::Sign, input, out_len, &mut |_| {})
}

/// `KEYCTL_PKEY_VERIFY` of signature `sig` over `data`: `EKEYREJECTED` (or
/// `EBADMSG` for a malformed padding) when it does not verify, `ENOSYS`
/// for "enc=raw", which Linux cannot verify.
pub fn pkey_verify(key: &Asym, info: &str, data: &[u8], sig: &[u8]) -> Result<(), i32> {
    let p = parse_info(info)?;
    let q = query_params(key, &p)?;
    check_sizes(&q, PkeyOp::Verify, data.len(), sig.len())?;
    let (alg, _) = determine(&p, PkeyOp::Verify)?;
    let rsa = RsaKey::new(key)?;
    match alg {
        RsaAlg::Raw => Err(ENOSYS),
        RsaAlg::Pkcs1(info) => pkcs1_verify(&rsa, info, sig, data),
    }
}

// ---------------------------------------------------------------------------
// The encrypted key type
// ---------------------------------------------------------------------------

const ENC_MIN_DATA_SIZE: i64 = 20;
const ENC_MAX_DATA_SIZE: i64 = 4096;
const ENC_HASH_SIZE: usize = 32;
const ENC_IV_SIZE: usize = 16;
const ECRYPTFS_MAX_KEY_BYTES: i64 = 64;
/// `sizeof(struct ecryptfs_auth_tok)`, the payload of an ecryptfs key.
const ECRYPTFS_AUTH_TOK_SIZE: usize = 737;

/// An `encrypted` key: its format, master key description, decrypted data
/// length as given, IV and decrypted data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedKey {
    pub format: Vec<u8>,
    pub master_desc: Vec<u8>,
    pub datalen: Vec<u8>,
    pub iv: [u8; 16],
    pub decrypted: Vec<u8>,
}

/// Splits as C's `strsep(&s, " \t")` does.
struct Strsep<'a> {
    rest: Option<&'a [u8]>,
}

impl<'a> Iterator for Strsep<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let s = self.rest?;
        match s.iter().position(|&c| c == b' ' || c == b'\t') {
            Some(i) => {
                self.rest = Some(&s[i + 1..]);
                Some(&s[..i])
            }
            None => {
                self.rest = None;
                Some(s)
            }
        }
    }
}

#[derive(PartialEq, Eq)]
enum EncCmd {
    New,
    Load,
    Update,
}

struct EncParsed<'a> {
    cmd: EncCmd,
    format: Option<&'a [u8]>,
    master: &'a [u8],
    datalen: &'a [u8],
    hex: Option<&'a [u8]>,
    decrypted: Option<&'a [u8]>,
}

/// `valid_master_desc`: "user:" or "trusted:" and a name; on update the
/// prefix must stay the same.
fn valid_master_desc(new: &[u8], orig: Option<&[u8]>) -> Result<(), i32> {
    let prefix_len = if new.starts_with(b"trusted:") {
        8
    } else if new.starts_with(b"user:") {
        5
    } else {
        return Err(EINVAL);
    };
    if new.len() == prefix_len {
        return Err(EINVAL);
    }
    if let Some(orig) = orig
        && orig.get(..prefix_len) != Some(&new[..prefix_len])
    {
        return Err(EINVAL);
    }
    Ok(())
}

/// `datablob_parse`, for instantiation or (`update`) for an update.
fn enc_parse(blob: &[u8], update: bool) -> Result<EncParsed<'_>, i32> {
    let mut it = Strsep { rest: Some(blob) };
    let keyword = it.next().ok_or(EINVAL)?;
    let cmd = match keyword {
        b"new" => Some(EncCmd::New),
        b"load" => Some(EncCmd::Load),
        b"update" => Some(EncCmd::Update),
        _ => None,
    };
    let p = it.next().ok_or(EINVAL)?;
    let (format, master) = match p {
        b"default" | b"ecryptfs" | b"enc32" => (Some(p), it.next()),
        _ => (None, Some(p)),
    };
    let master = master.ok_or(EINVAL)?;
    valid_master_desc(master, None)?;
    let datalen = if update { &b""[..] } else { it.next().ok_or(EINVAL)? };
    let mut parsed =
        EncParsed { cmd: EncCmd::New, format, master, datalen, hex: None, decrypted: None };
    match cmd {
        Some(EncCmd::New) if !update => parsed.decrypted = it.next(),
        Some(EncCmd::Load) if !update => {
            parsed.cmd = EncCmd::Load;
            parsed.hex = Some(it.next().ok_or(EINVAL)?);
        }
        Some(EncCmd::Update) if update => parsed.cmd = EncCmd::Update,
        _ => return Err(EINVAL),
    }
    Ok(parsed)
}

/// `kstrtol(s, 10)`.
fn kstrtol(s: &[u8]) -> Option<i64> {
    let (neg, digits) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let digits = digits.strip_suffix(b"\n").unwrap_or(digits);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut v: i64 = 0;
    for &c in digits {
        v = v.checked_mul(10)?.checked_add((c - b'0') as i64)?;
    }
    Some(if neg { -v } else { v })
}

/// The decrypted data length `encrypted_key_alloc` accepts.
fn enc_datalen(
    format: Option<&[u8]>,
    datalen: &[u8],
    decrypted: Option<&[u8]>,
) -> Result<usize, i32> {
    let dlen = kstrtol(datalen).ok_or(EINVAL)?;
    if !(ENC_MIN_DATA_SIZE..=ENC_MAX_DATA_SIZE).contains(&dlen) {
        return Err(EINVAL);
    }
    if let Some(d) = decrypted
        && (d.len() as i64 != dlen * 2 || !d.iter().all(u8::is_ascii_hexdigit))
    {
        return Err(EINVAL);
    }
    match format {
        Some(b"ecryptfs") if dlen != ECRYPTFS_MAX_KEY_BYTES => return Err(EINVAL),
        Some(b"enc32") if dlen != 32 => return Err(EINVAL),
        _ => {}
    }
    Ok(dlen as usize)
}

fn unhex(s: &[u8]) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_chunks::<2>()
        .0
        .iter()
        .map(|c| {
            let h = (c[0] as char).to_digit(16)?;
            let l = (c[1] as char).to_digit(16)?;
            Some((h * 16 + l) as u8)
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `get_derived_key`: SHA-256 of "ENC_KEY\0" or "AUTH_KEY\0" and the master
/// key, in a zeroed buffer of `9 + master length` bytes, at least 32.
fn derived_key(auth: bool, master: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; (9 + master.len()).max(ENC_HASH_SIZE)];
    let label: &[u8] = if auth { b"AUTH_KEY" } else { b"ENC_KEY" };
    buf[..label.len()].copy_from_slice(label);
    buf[label.len() + 1..label.len() + 1 + master.len()].copy_from_slice(master);
    hash("sha256", &[&buf]).unwrap_or_default()
}

impl EncryptedKey {
    /// `add_key("encrypted", desc, payload)`: "new [format] master datalen
    /// [hex data]" or "load [format] master datalen hex". The master key
    /// comes from `master`, given the master description ("user:name");
    /// `None` is `ENOKEY`. `EINVAL` for a malformed payload or a bad
    /// HMAC, `EOPNOTSUPP` for a "trusted:" master key.
    pub fn instantiate(
        desc: &[u8],
        payload: &[u8],
        master: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
        random: &mut dyn FnMut(&mut [u8]),
    ) -> Result<EncryptedKey, i32> {
        let blob = enc_blob(payload)?;
        let p = enc_parse(blob, false)?;
        let dlen = enc_datalen(p.format, p.datalen, p.decrypted)?;
        if p.format == Some(b"ecryptfs")
            && (desc.len() != 16 || !desc.iter().all(u8::is_ascii_hexdigit))
        {
            return Err(EINVAL);
        }
        let mut key = EncryptedKey {
            format: p.format.unwrap_or(b"default").to_vec(),
            master_desc: p.master.to_vec(),
            datalen: p.datalen.to_vec(),
            iv: [0; 16],
            decrypted: vec![0; dlen],
        };
        if let Some(h) = p.hex {
            key.load(p.format.is_some(), h, master)?;
        } else if let Some(d) = p.decrypted {
            random(&mut key.iv);
            key.decrypted = unhex(d).ok_or(EINVAL)?;
        } else {
            random(&mut key.iv);
            random(&mut key.decrypted);
        }
        Ok(key)
    }

    /// `encrypted_key_decrypt`.
    fn load(
        &mut self,
        has_format: bool,
        h: &[u8],
        master: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
    ) -> Result<(), i32> {
        let enc_len = self.decrypted.len().div_ceil(16) * 16;
        if h.len() != (ENC_IV_SIZE + 1 + enc_len + ENC_HASH_SIZE) * 2 {
            return Err(EINVAL);
        }
        let iv = unhex(&h[..32]).ok_or(EINVAL)?;
        let enc = unhex(&h[34..34 + 2 * enc_len]).ok_or(EINVAL)?;
        let mac = unhex(&h[34 + 2 * enc_len..]).ok_or(EINVAL)?;
        self.iv.copy_from_slice(&iv);
        let mk = self.master_key(master)?;
        let blob = self.datablob(&enc);
        let skip = if has_format { 0 } else { self.format.len() + 1 };
        let auth = derived_key(true, &mk);
        let calc = hmac("sha256", &auth, &[&blob[skip..]]).ok_or(EINVAL)?;
        if calc != mac {
            return Err(EINVAL);
        }
        let plain = aes_cbc_decrypt(&derived_key(false, &mk), &self.iv, &enc).ok_or(EINVAL)?;
        let n = self.decrypted.len();
        self.decrypted.copy_from_slice(&plain[..n]);
        Ok(())
    }

    /// `request_master_key`.
    fn master_key(&self, master: &dyn Fn(&[u8]) -> Option<Vec<u8>>) -> Result<Vec<u8>, i32> {
        if self.master_desc.starts_with(b"trusted:") {
            return Err(EOPNOTSUPP);
        }
        if !self.master_desc.starts_with(b"user:") {
            return Err(EINVAL);
        }
        master(&self.master_desc).ok_or(ENOKEY)
    }

    /// The datablob the HMAC covers: format, master description and
    /// datalen, each NUL-terminated, the IV, a NUL and the encrypted data.
    fn datablob(&self, enc: &[u8]) -> Vec<u8> {
        [
            &self.format[..],
            b"\0",
            &self.master_desc,
            b"\0",
            &self.datalen,
            b"\0",
            &self.iv,
            b"\0",
            enc,
        ]
        .concat()
    }

    fn enc_len(&self) -> usize {
        self.decrypted.len().div_ceil(16) * 16
    }

    fn datablob_len(&self) -> usize {
        self.format.len()
            + self.master_desc.len()
            + self.datalen.len()
            + 3
            + ENC_IV_SIZE
            + 1
            + self.enc_len()
    }

    /// The bytes Linux charges to the owner's quota for the key.
    pub fn quota_len(&self) -> usize {
        let payload =
            if self.format == b"ecryptfs" { ECRYPTFS_AUTH_TOK_SIZE } else { self.decrypted.len() };
        payload + self.datablob_len() + ENC_HASH_SIZE + 1
    }

    /// The length of what `KEYCTL_READ` gives, which it returns without the
    /// master key when the buffer is shorter.
    pub fn read_len(&self) -> usize {
        self.datablob_len() + ENC_IV_SIZE + 1 + self.enc_len() + 2 * ENC_HASH_SIZE
    }

    /// `KEYCTL_READ`: "format master datalen hex", the hex being of the IV,
    /// a zero byte, the data encrypted with AES-256-CBC under SHA-256 of
    /// "ENC_KEY\0" and the master key, and HMAC-SHA256 of the datablob
    /// under SHA-256 of "AUTH_KEY\0" and the master key.
    pub fn read(&self, master: &dyn Fn(&[u8]) -> Option<Vec<u8>>) -> Result<Vec<u8>, i32> {
        let mk = self.master_key(master)?;
        let mut plain = self.decrypted.clone();
        plain.resize(self.enc_len(), 0);
        let enc = aes_cbc_encrypt(&derived_key(false, &mk), &self.iv, &plain).ok_or(EINVAL)?;
        let blob = self.datablob(&enc);
        let mac = hmac("sha256", &derived_key(true, &mk), &[&blob]).ok_or(EINVAL)?;
        let mut out = Vec::with_capacity(self.read_len());
        for part in [&self.format, &self.master_desc, &self.datalen] {
            out.extend_from_slice(part);
            out.push(b' ');
        }
        let tail = [&self.iv[..], &[0], &enc, &mac].concat();
        out.extend_from_slice(hex(&tail).as_bytes());
        Ok(out)
    }

    /// `KEYCTL_UPDATE` with "update master": the key with a new master key
    /// description of the same kind.
    pub fn update(&self, payload: &[u8]) -> Result<EncryptedKey, i32> {
        let blob = enc_blob(payload)?;
        let p = enc_parse(blob, true)?;
        valid_master_desc(p.master, Some(&self.master_desc))?;
        enc_datalen(Some(&self.format), &self.datalen, None)?;
        Ok(EncryptedKey { master_desc: p.master.to_vec(), ..self.clone() })
    }
}

/// The payload as the C string Linux parses: `EINVAL` when empty or over
/// 32767 bytes.
fn enc_blob(payload: &[u8]) -> Result<&[u8], i32> {
    if payload.is_empty() || payload.len() > 32767 {
        return Err(EINVAL);
    }
    let end = payload.iter().position(|&b| b == 0).unwrap_or(payload.len());
    Ok(&payload[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        unhex(s.as_bytes()).expect("hex")
    }

    // Test vectors from LTP's keyctl tests (keyctl_dh_data.h,
    // keyctl_pkey_data.h, keyctl05.c and keyctl23.c), as hex.
    const DH_PRIME: &str = concat!(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22",
        "514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6",
        "f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d",
        "c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb",
        "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e8603",
        "9b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa0510",
        "15728e5a8aacaa68ffffffffffffffff",
    );
    const DH_PRIV: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const DH_BASE: &str = concat!(
        "dd5d87a6f9df57f13df2c658e501abd72adba34863613bd16769eef955258e3611ee8ec542a426e3",
        "75c6b4d83b717c97f88504b43acc5df03a4904e88d2619dfb7fb3cda68bc136c468dfedf1c5a5b73",
        "046408866fec8949beb587a0a4b6e6c0def5f24405385184a69e9dce4208f363adb0e1ce881863eb",
        "8d82d4aead5e1c195047d70d9bdc447bda027684b4351d98503fee1bcf827ffd07501701c7f39124",
        "22dd2f42b26cf40adde07d63e235f42f6521402a90dd2cea4a2e177640742d3cac853e96fa494413",
        "fee945972b2423a0f51becf28528c9db926002c50ffe2b1a97c978cf488ba29bbb472e7e63282ddd",
        "320a15a072d8176075204f7ded293561",
    );
    const DH_SECRET: &str = concat!(
        "61fc0d4d01cee152340f52b45328aa11d86e92ce8e8f7ba29180f62d999bc7714cbb05efde22bddf",
        "6f8dbb00df4efa1c14ea5420acec51cdbdd063fc357bd9ab367f1b67c3b1514e2d190550be1d4451",
        "5ffe65f8f612ad6cc58496d9c3c9397d8798a78e524d1f26be6214f466cf9a904d28dd29116e510c",
        "7b181eac5549ce1defcc6ca20e80d30d24c0776887f8a3050f8daa586bbb6bd076ea875cc33eef19",
        "669ec7d44e85df06610b949cd35823a7b1f636af6b4cf18840d45f6e9d1fa73c8bc271ba87cdc29b",
        "33cf18ee598ef66c76ccedcc09fee1f8ce5c78b3b9e3f52914aa67d0b5cb7a7ed12e8397f16bfbe4",
        "fbebdd18540d4ca765c10c11adea839f",
    );
    const DH_KDF: &str = "6639ec413133e6c06167285161f78cd7c055c9cc8346f3aa62edca90992dc407";
    const CERT29: &str = concat!(
        "30820317308201ffa003020102021452d43ecb8a14a85b02723b64f99d52a3ca610878300d06092a",
        "864886f70d01010b0500301a3118301606035504030c0f6c74702d6b657963746c2d706b65793020",
        "170d3236303930313039313132365a180f32313236303830383039313132365a301a311830160603",
        "5504030c0f6c74702d6b657963746c2d706b657930820122300d06092a864886f70d010101050003",
        "82010f003082010a0282010100d397611408b7ca7354d039b9af6212cc90de86eb13910683f34148",
        "d7f7c550261f2d5309435925810498844c1032ee6360de1a7663c35d7912f2bf33d64cf247560341",
        "51747f7d8064321c1c19ac1208d6d227216cda40ea3b9c7fa8ee860a18cac3b66ae890ccaf441c03",
        "dd57fc67baae5b7b3ec3dacccf9690ad724d447d46a57c834b745d1620334b8adf8b14216fbbb3d9",
        "97efd2bf4f41018669a0e6ce7bddb95c35ce2f0c5d236071d709051c70b402af75b6cd2fbfbad035",
        "c6d00950cff9d9e8dc3bca1945631c88c94ca709e62c7e81d006e437b942c93b5cb570c4b52014a1",
        "5137f258a89c11c170e6b045f3c523e7eea79d9b2b81efeb63f29315210203010001a3533051301d",
        "0603551d0e041604141969a70c58c5d7b30b26ce2a3465aea7adf6ab74301f0603551d2304183016",
        "80141969a70c58c5d7b30b26ce2a3465aea7adf6ab74300f0603551d130101ff040530030101ff30",
        "0d06092a864886f70d01010b05000382010100018a1b5491bbf6d9c5094c9fd264afcf4e45dac631",
        "0f557de783a1fe5142dab48bbaf715aedef30544b7c2400333882b32ee133b50b438323ba6df586a",
        "46480dbc4abfceb5987f5ccb04a8bf7b2804cf3baa4d16b85f0a60cadee1871a40c12c9329307921",
        "caa358ea8d93961769a9af16af6f446a4e599d4d8e697a1162bc997e8ea6702a7bbb33de81226d7f",
        "18a6251f84039b8e881b5c08f8b1f12739bb066c54fab99ce15bffc1f224f079bdb19fa5b89c1196",
        "6ba10564414556f35b515d7f5d501548d068878a3986ae03dd2a7f48257bded48b3cba07c653bb2b",
        "679800c55d38c0c4518e24c98583b316797ccc76ed021f912ca723ae7bfdd509097028",
    );
    const PKCS8: &str = concat!(
        "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100d397",
        "611408b7ca7354d039b9af6212cc90de86eb13910683f34148d7f7c550261f2d5309435925810498",
        "844c1032ee6360de1a7663c35d7912f2bf33d64cf24756034151747f7d8064321c1c19ac1208d6d2",
        "27216cda40ea3b9c7fa8ee860a18cac3b66ae890ccaf441c03dd57fc67baae5b7b3ec3dacccf9690",
        "ad724d447d46a57c834b745d1620334b8adf8b14216fbbb3d997efd2bf4f41018669a0e6ce7bddb9",
        "5c35ce2f0c5d236071d709051c70b402af75b6cd2fbfbad035c6d00950cff9d9e8dc3bca1945631c",
        "88c94ca709e62c7e81d006e437b942c93b5cb570c4b52014a15137f258a89c11c170e6b045f3c523",
        "e7eea79d9b2b81efeb63f293152102030100010282010052b0ba53a6048dadfcdb5373e9c29e2e2b",
        "ff8b229b86f5d0e364041fc2c8edc5b831725e105fea743d638d705c744b0db371994de3371a7492",
        "9f237212b2078d31641c46c50c7df38b34ba1f9138d9e37270b6b22d642e325c11912267f5224506",
        "18ee5561861537f99a29387b863cd38c085c65ef0cb735f95599332e5731cd900e99cdb35fb57e16",
        "867347c0ab6b53a18f3534d382287c658ea802e2f3836d5443234595f174bcf17d6416e501c65abb",
        "19fa5401a4265a2fa420b74c612c2a78ed2fcb6726f16b0ce38a279e4f00064e1d58070e1c0d0c8c",
        "3aa71dbeb816dfe1b313096ae750802fa13822ae2d58520796109871e1ce26884c5e115f6cd23102",
        "818100f364078c913c5a48144ac14a1a93e5b83a3cfe41604971cceeaf0eac0c855148f936cf8cc5",
        "5848a24946d133928c40faf076c1888f23068b761589c0cd4b61d8c6a2cf9c04403b7a24c197b936",
        "a68bffe7efa5563c55bf6d7433eb67b34afe81aaadd9432359ef51992b58a6c19c095c88a0711c1e",
        "9439cd827dea41a89e051702818100de8d9c20a12f473dac5f15ce55526a2f3da0b084926cd60f3c",
        "2e96c02616a90cc0ec0650e7581dfbcc9a642f1b3a69b551caf72ea5011ec9238588869e958c03fb",
        "af466c7c9a4b00b7271873ea1dc6551d4cca70b1b2762192f06fa881826f527036e0660f4f7ddaf2",
        "bbcaaa2d3c272ac4a6160aec9146bc7d3287d03b808a8702818100cf076d2c7275c5cdbe0500794a",
        "3637970762ce5b49cdef51044e3fcab533c9baaad1a6a5f54f6d292def610fdf3e121fe1df022c68",
        "a4c0726c5551c1805ef8b1edf49b67f86db2a9e90e0b42ee6ba8765b118bafd8ce8f704901c8e182",
        "aeede1da0edad9b2fe530533a69d57eb24110a76e512917aa956a9aaaff44d396280ad02818100c6",
        "207ba5f0d90e2b319154f063b503231b523ad34b27e94996e24302bce5df89a3167c68fa0bd065a2",
        "38b087df4d995dfa7b1ea33ff2475df9699fa978f4d9b9920ef03b1492a7c2f34ab2d23ed25306e3",
        "16c202a1afa6cb2ced2ffa6b919b5960dcf9d8e2387a6ab93dc5a6caae8a8fe0919b7e0e2d273416",
        "a12d978be15b7102818034b523d07fa51f3fa2fcb8505f167665674862bef898075ca9c27959daa0",
        "b81b5073d67417ba09db08c9fbe52ce5eade321a51dfb4a84eb5932d589036aaa41253543db0bc52",
        "b39a0b6e73b25758beb8fca0aa0269eac41be43e42f0f82da2b3a93e57fe1ae9a6ca057f9b60d728",
        "4a6ad7f4e4a15d5c4fedd3aab7b9fc87cdc5",
    );
    const CERT23: &str = concat!(
        "308203253082020da003020102021452adef01cabb6417a71aa7cb2f82446eec5a2e2c300d06092a",
        "864886f70d01010b05003021311f301d06035504030c166c74702d6b657963746c32332d756e7472",
        "75737465643020170d3236303930323039323334395a180f32313236303830393039323334395a30",
        "21311f301d06035504030c166c74702d6b657963746c32332d756e7472757374656430820122300d",
        "06092a864886f70d01010105000382010f003082010a0282010100d5ee8dec858e29c7e7f83fedc8",
        "82b21795f4e0990284c5b346628c8ad389d56225a7c892ccc5642080b7f3c240dcf0f0d8855f5861",
        "77d6d53a32ec811525b408216df3d680a6915a539e54495b916b740bb599d54946415667b4ed1782",
        "960340d70d0a00953cb7759e61abe9104aa99021d2b43dd083480c59a9d7be7b4c75f0d18a291c06",
        "35296d3c6eb9ce11a91b4df7fd6d2e027fbe45b711ae1dbb7002aec1b3313d99d97001bdead30d04",
        "e02fac79e4b20c96ba669ecf7213a33744032de95c716f3571f8dc58a31f57885979e67e379bc9a3",
        "36035ccb30925e9e4348a23e7fdcb8e36ae68c18b2424cbb2d6a6c5fd1c1d5333bdb8c3ca2ecaaed",
        "cee1d10203010001a3533051301d0603551d0e04160414d38dd1e4774ee2b2b6ab3158697b2731ce",
        "00cd60301f0603551d23041830168014d38dd1e4774ee2b2b6ab3158697b2731ce00cd60300f0603",
        "551d130101ff040530030101ff300d06092a864886f70d01010b050003820101001eb95216f2efca",
        "bc3593b438b8abfe731a06509958c4a8f426b1e18e0bd3e7a88d1fa0794c9fdd3af0b7f218fc9911",
        "458febc9f2482e4a7b2437a4bc52968076465927b5a0075b6c385cde9576fc21b81e7e133e5995f9",
        "39dbd5413d8dfd4c1a4bdd413b2758f872a37097c6b90e4e3c08ba2fa9556d23ddc40a43ad20750d",
        "eabc496cd2875946723e779b2963380a2f61ccdad021476f9f19260cbb77228dc76501254b6938ae",
        "6e164f7035abea76e437e4926bf06ec54cc137c128a678c790b4eabb8d12e130e17b76c365c3997b",
        "b3b19ae973b24d082aa46742ef7cf5673ea478e104935e1bf9aee15a7f4238b793fb27ff1c7edd8a",
        "7110cb65c9f20f9e7d",
    );
    const CERT05: &str = concat!(
        "308201d33082017da003020102020900922a76ff0c00fb9a300d06092a864886f70d01010b050030",
        "45310b30090603550406130241553113301106035504080c0a536f6d652d53746174653121301f06",
        "0355040a0c18496e7465726e6574205769646769747320507479204c7464301e170d313730373238",
        "3231343133345a170d3137303832373231343133345a3045310b3009060355040613024155311330",
        "1106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769",
        "646769747320507479204c7464305c300d06092a864886f70d0101010500034b003048024100de0b",
        "1c24e20df817f2c36fc9723e9db02d47e4c48587edde06e3f3e94c356ce4cb0e4428236676ec4edf",
        "1093921e52fbdf5c08e7240466e306052756fb3e91310203010001a350304e301d0603551d0e0416",
        "04146f393a46df2963de547b6c3106d09f3616fb9cbf301f0603551d230418301680146f393a46df",
        "2963de547b6c3106d09f3616fb9cbf300c0603551d13040530030101ff300d06092a864886f70d01",
        "010b050003410073f04b6256edf08b7ec4757898a27a6e751fde9ba0be1a1f864413cd45067f86de",
        "f6364eb615faf5b034d25e0bb32c035a5a28975e7bdf6375838d69dad659bd",
    );
    const CA: &str = concat!(
        "3082023030820199a0030201020214573b732363963a215fe780cf81c182cdefdf9fcb300d06092a",
        "864886f70d01010d050030293111300f060355040a0c084657452054657374311430120603550403",
        "0c0b46574520546573742043413020170d3236313130383133313331375a180f3231323631303135",
        "3133313331375a30293111300f060355040a0c0846574520546573743114301206035504030c0b46",
        "5745205465737420434130819f300d06092a864886f70d010101050003818d0030818902818100e2",
        "174946c567485071e35dfed46e1a8823c95a257103b2cb536145d42fc0bb333537fd5ee7b2b86971",
        "036801853f22f36d424258aa2b28a528c168a0b40ae7a7a86d143628939ccb40479ab3abddf68751",
        "0181161e2d77855e6e691c442cd4e24b39b741b81fd46eb3e58c7a507f751c7b5a082ed26f05f1b3",
        "05f0e4847b14b10203010001a3533051301d0603551d0e04160414b62ae1a1706c92ba811ef2b758",
        "0f0bef0f7b5b65301f0603551d23041830168014b62ae1a1706c92ba811ef2b7580f0bef0f7b5b65",
        "300f0603551d130101ff040530030101ff300d06092a864886f70d01010d0500038181007e9e0a0b",
        "1b839ffdba37254da451ad9917588a5bd9b5264f0fdddc0c0790e57d36796757819e4120497f1cac",
        "7780a5a2020dd21d32f5e9f918448c6a2c9c5252b395d9876fd9283bdff423d2bbf92d0bd59ec625",
        "9a17d8b41a8a88434954e689685f95264ffbdd270ec09c78b6903e7ee1f5efcfb01457bc8d23540a",
        "7e0d23e6",
    );
    const LEAF: &str = concat!(
        "3082020930820172a00302010202021234300d06092a864886f70d01010c050030293111300f0603",
        "55040a0c0846574520546573743114301206035504030c0b46574520546573742043413020170d32",
        "36313130383133313331375a180f32313236313031353133313331375a302531143012060355040a",
        "0c0b4578616d706c65204f7267310d300b06035504030c046c65616630819f300d06092a864886f7",
        "0d010101050003818d0030818902818100bcc5c52c81887b0ce3fa0943bf24cee8903a26093bc463",
        "8021b40f768670b1c19cd534da0e301502377292d7703b0340cb5bd136ad59e464a20460fd74afeb",
        "b11248721b3a62683fb571b2451542ef3dd4d355017ca9f1dc2d76c41c3b7c79e872e84717dd7371",
        "62bf329f0adc46053065d47bcff9face5bd35a53892ea81dd30203010001a3423040301d0603551d",
        "0e0416041412f6570f00d3c7b6480045fb6c0f10c5d7dc6c48301f0603551d23041830168014b62a",
        "e1a1706c92ba811ef2b7580f0bef0f7b5b65300d06092a864886f70d01010c0500038181002539e0",
        "e4f933bf0d39efc1e14cad61d46f32f434082ae0f29bbbd48e5249076307b53ca05bc494233d1365",
        "6e37346504d7f5b3aa70be34edab979d6b3041fedeeb7e05a69be38ab6b69496426ccc9a532576ad",
        "c6cc20924e2ec33513ffc47694eaa3e338c8d3ebbe2022d8d2ce90f42778e5ec7158a69df0535395",
        "172ba4dce3",
    );
    const BARE: &str = concat!(
        "308201c63082012fa003020102020300a1b2300d06092a864886f70d010105050030293111300f06",
        "0355040a0c0846574520546573743114301206035504030c0b46574520546573742043413020170d",
        "3236313130383133313333315a180f32313236313031353133313333315a30253114301206035504",
        "0a0c0b4578616d706c65204f7267310d300b06035504030c046c65616630819f300d06092a864886",
        "f70d010101050003818d0030818902818100bcc5c52c81887b0ce3fa0943bf24cee8903a26093bc4",
        "638021b40f768670b1c19cd534da0e301502377292d7703b0340cb5bd136ad59e464a20460fd74af",
        "ebb11248721b3a62683fb571b2451542ef3dd4d355017ca9f1dc2d76c41c3b7c79e872e84717dd73",
        "7162bf329f0adc46053065d47bcff9face5bd35a53892ea81dd30203010001300d06092a864886f7",
        "0d0101050500038181003dc84fe91319177a8420146dd24b172eb1cdd14287e27a0b990b832df26c",
        "5955682095dbc02c0f9bbc197a5a26dd4be12fe0e82918d440371138fa5aea608feed210ff72b9f2",
        "32f509a9fef9171543a98885dbd33a93011bca6b1bd8d4151fc8071462251a0ba1257c4e5cef29b3",
        "f6855953b4cf2e486d4250b626111dead2e6",
    );
    const MODEXP_M: &str = concat!(
        "c43658625af0f3e0d9a54a0d7b25331f4d6bfd8fa506bfc51025dbe58e725d57d30aad4b45038e22",
        "0bc4621b9439852083d9fca716c40a33acd51e6699f9823c118dc10e774520d7e98d7c358a84c15c",
        "aad14268108727563ff4bb8cf703c9ffe16682717c9bbfae80ca17b703be0e66d868c2cf1d4a2b12",
        "b6a20bb02edf0743175e99412607ad5f76ab14759da618fd7bf78a4d9f8f5ffba5f80a0a58994953",
        "040e1e30c9ed0248fc9799a707e36d6004762a223c9f90c95ac96628c438183619322fed157cf9c6",
        "b16e2d5cabeb959208f0ebd4950cddd9ce97b5bdf073eed1f149f542e935b87017346b4501eaf614",
        "1de9ea6670d3da1fc735df5ef7697fb9",
    );
    const MODEXP_B: &str = concat!(
        "077d6ad103b91f95365d68577a296e7ef077e0597ee18bc3a671c462dcec669027b9ad0a83178876",
        "e99afdd579c4c9c777b54b2790ae2cd8fba355f46871014cdead2e2791eef8458c3cdb2d665a7b0a",
        "4adb41ce779a93a99226f446db4bc46a8f69260a228ba87442a1244e2e3761aba601ca242780aa87",
        "9951fff4f991a81c63373ac55ef18658a295d4eff35b6106f1e77124ed49b137106d208ead31c813",
        "48486129fc1d9d7f1ff9fe966844aa138411eb0dde6d082ac7e1da6099d795a8486261790b2f7cb5",
        "c36ec124ce01e15560eaba017ad051121213ca8212f7c6f1048aa604f0d0f2aa58695187b8a518e0",
        "65e3eb74113cb033354fc7eefadf23a7cda6c23fc86ee6",
    );
    const MODEXP_E: &str = concat!(
        "b6d288d4652ea61314180ee8121e3cc4b87ec0d17259023bc9782a58cb26e7a552d037e4b85a4eab",
        "fbd67b31d729a460d911b0dc27a40502f8d07ea044f2d5a4f1689e5fe87212b0949606b3283c4412",
        "f6a11b92cf58440cb33bfa31b3e174eb1bb039fa5868c99b31007342a41b657a4166c3fba8094805",
        "d11776a4d15703e0607741867c362491d72f9ecdd454f1e81a644d9287a0eabff0689ae11e956a7d",
        "c4e145896fa19d466a94427d2f84ea0fc7154f271fb661b44669165f4bb19d02701861c0d092e07f",
        "84eb1e73c7f3c8a0bbc9a6e0708963bb2b833e28e1ae6a00984c6df8d13d74f3dec4ac467888fa7a",
        "eed66a5ac86b7f7f0b9ab36679d6dedb",
    );
    const MODEXP_R: &str = concat!(
        "69d70804d8b598d61a42c612012a314b6db08ec8f00372ea66afbc4a4777137639f047927ef61284",
        "eb3e72f4b211686b7b60ea25b4a460648b967a5c8686e74cfd539b99484de465c8c9458a34a5c591",
        "36c57d1b7e57c566cd57031d48c0166ee050d7e12d91a45b49fdd8a69ede6fdd04e0e2fbc6591945",
        "5455fe5920535d79caddc66f624450fbc70e646041f4e826c7c4e4df0f21c0ee54cda1688f4b9520",
        "259ee9c0d396dac8369c9265abcb8526503cfff25b360c792bacdc779719b57b17313e078da16514",
        "2d366894c74419f6bac3aaedc6e6ae71f943e89bea59aa8ac04ccca7f5d7160cf4407b2604fccb7c",
        "d3e5646589c33218d9c842ea21194b83",
    );
    const EVEN_M: &str = concat!(
        "e2b471b2e631d17176658aa25d19ee50c433af81d9f312c9346d22469db0575eb712b01ad0db4406",
        "2d41e6dc0995c13a7910f44ac075f93a5ff1eeddee4e3d69675125ff0fff977125b30b0b98f06045",
        "17eecda947caf4a2a116716583d4621dc481b81040382a0c2d09ba039acdabc3ea49400b81e50008",
        "d80c386144",
    );
    const EVEN_B: &str = concat!(
        "08f36d31e8c5f8a3f2e80dcc197fe4f416272ef8a588ca8e3c5a3c8204d01707780f7087574d4142",
        "f83408d67f95a290e3f3d9ff9f2cb87a7a6bd20911b3d18022e3c1bbce83d9479c3480251adbd2db",
        "62ee57a9865c7b2ceccc2c6076d18b48943c7ff71f8021ef3275a66c1ae32996b4",
    );
    const EVEN_E: &str =
        "0d7a251a0926ece37d772a42ab569fdf9fe20c4e7af82184d0ea2383bc6655712a5578f190db";
    const EVEN_R: &str = concat!(
        "65685cd97f383b3450bb0338d2a678e0165dc6c346bc604590a1a919ce368a8307eb94f58fa5d6bc",
        "902e6d5603cfe07afb7519aaac69a69e5fde9807877ee27dc884097905eb287c85aac3b8fc490872",
        "7e7248b0e785e4ec8ce06827af40dd374eb08c786a3f83a1aa5538714e75ba60512c8e040400abba",
        "320390dc84",
    );

    // SHA-256 of "fwe" signed with the key of PKCS8 by OpenSSL
    // (`openssl dgst -sha256 -sign`).
    const FWE_DIGEST: &str = "8ed0bc41e89fd37b758b06b931c934218b61c4da4825832fadd16a081acc8781";
    const FWE_SIG: &str = concat!(
        "cbcac1ccccacd2fff6f717e9ad003de5ba0dc196be280f9baae6b31b17ffdfd36cf57162ea05056e",
        "e7635e3eb61644934fc0d1ea5881666be38a0cbca78561dbd9c393366889a2b4a0ba65391f769bca",
        "0fa0570d85b3b1a705aa63111089b3f0787af2e4cbb609335e231dceb8c1b0ef906a7a163769b9e9",
        "16a294cf222de5086abff488b909752cc2442b96047e6064f7343b05071033e34adb468dbbf2c346",
        "2a39b6e007a716830d1d7841c110c08253e7b987a6f98994d9847f94e37ce7c15c840af72d90f713",
        "9dbc0850359320348268e4c3375002ff51e9a076f657622ea9e7f2a515e9b4bc93c2d2801ec41cc5",
        "9b363d27320931f5ea39b6b482687b1f",
    );

    const MSG_448: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const MSG_896: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

    #[test]
    fn sha_fips_180_4() {
        let cases: &[(&str, &[u8], &str)] = &[
            ("sha1", b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            ("sha1", b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            ("sha1", MSG_448, "84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
            ("sha224", b"abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
            ("sha224", MSG_448, "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"),
            ("sha256", b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("sha256", b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("sha256", MSG_448, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
            (
                "sha384",
                b"abc",
                concat!(
                    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed",
                    "8086072ba1e7cc2358baeca134c825a7"
                ),
            ),
            (
                "sha384",
                MSG_896,
                concat!(
                    "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712",
                    "fcc7c71a557e2db966c3e9fa91746039"
                ),
            ),
            (
                "sha512",
                b"",
                concat!(
                    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
                    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                ),
            ),
            (
                "sha512",
                b"abc",
                concat!(
                    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                ),
            ),
            (
                "sha512",
                MSG_896,
                concat!(
                    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018",
                    "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
                ),
            ),
        ];
        for (name, msg, want) in cases {
            assert_eq!(hash(name, &[msg]).unwrap(), h(want), "{name}");
            // The same in pieces that straddle block boundaries.
            let (a, b) = msg.split_at(msg.len() / 3);
            assert_eq!(hash(name, &[a, b]).unwrap(), h(want), "{name} split");
        }
        assert_eq!(hash("md5", &[b"abc"]), None);
        assert_eq!(hash_size("sha384"), Some(48));
    }

    #[test]
    fn sha256_million_a() {
        let chunk = [b'a'; 1000];
        let parts: Vec<&[u8]> = (0..1000).map(|_| &chunk[..]).collect();
        assert_eq!(
            hash("sha256", &parts).unwrap(),
            h("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        );
    }

    #[test]
    fn hmac_rfc_4231() {
        let k1 = [0x0b; 20];
        let k3 = [0xaa; 131];
        let cases: &[(&[u8], &[u8], &str, &str)] = &[
            (&k1, b"Hi There", "sha224", "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"),
            (
                &k1,
                b"Hi There",
                "sha256",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "sha384",
                concat!(
                    "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e",
                    "8e2240ca5e69e2c78b3239ecfab21649"
                ),
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "sha512",
                concat!(
                    "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
                    "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
                ),
            ),
            (
                &k3,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "sha256",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                &k3,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "sha512",
                concat!(
                    "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352",
                    "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
                ),
            ),
            (
                &k3,
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                "sha384",
                concat!(
                    "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5",
                    "a678cc31e799176d3860e6110c46523e"
                ),
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "sha1",
                "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            ),
        ];
        for (key, msg, name, want) in cases {
            assert_eq!(hmac(name, key, &[msg]).unwrap(), h(want), "{name}");
        }
        assert_eq!(hmac("sha3-256", b"k", &[b"m"]), None);
    }

    #[test]
    fn aes_fips_197() {
        let pt = h("00112233445566778899aabbccddeeff");
        let key: Vec<u8> = (0u8..32).collect();
        let zero = [0u8; 16];
        for (len, want) in [
            (16, "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
            (32, "8ea2b7ca516745bfeafc49904b496089"),
        ] {
            let ct = aes_cbc_encrypt(&key[..len], &zero, &pt).unwrap();
            assert_eq!(ct, h(want), "AES-{}", len * 8);
            assert_eq!(aes_cbc_decrypt(&key[..len], &zero, &ct).unwrap(), pt);
        }
    }

    #[test]
    fn aes_cbc_sp800_38a() {
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = h("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let pt = h("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let ct = aes_cbc_encrypt(&key, &iv, &pt).unwrap();
        assert_eq!(ct, h("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"));
        assert_eq!(aes_cbc_decrypt(&key, &iv, &ct).unwrap(), pt);
        assert_eq!(aes_cbc_encrypt(&key, &iv, &pt[..17]), None);
        assert_eq!(aes_cbc_decrypt(&key, &iv, &pt[..15]), None);
        assert_eq!(aes_cbc_encrypt(&key[..15], &iv, &pt), None);
    }

    #[test]
    fn mod_exp_small() {
        assert_eq!(mod_exp(&[4], &[13], &[1, 241]), Some(vec![1, 189])); // 4^13 mod 497 = 445
        assert_eq!(mod_exp(&[7], &[], &[0, 0, 10]), Some(vec![1]));
        assert_eq!(mod_exp(&[7], &[5], &[1]), Some(vec![0]));
        assert_eq!(mod_exp(&[7], &[5], &[0, 0]), None);
        assert_eq!(mod_exp(&[3], &[200], &[]), None);
        // An even modulus, and a base larger than it.
        assert_eq!(mod_exp(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 3], &[3], &[100]), Some(vec![99]));
    }

    #[test]
    fn mod_exp_large() {
        // Values and results from Python's pow().
        let r = mod_exp(&h(MODEXP_B), &h(MODEXP_E), &h(MODEXP_M)).unwrap();
        assert_eq!(r, h(MODEXP_R));
        let r = mod_exp(&h(EVEN_B), &h(EVEN_E), &h(EVEN_M)).unwrap();
        assert_eq!(r, h(EVEN_R));
        // Leading zeros of the modulus do not count towards the length.
        let mut m = vec![0, 0];
        m.extend_from_slice(&h(MODEXP_M));
        assert_eq!(mod_exp(&h(MODEXP_B), &h(MODEXP_E), &m).unwrap(), h(MODEXP_R));
    }

    #[test]
    fn divrem_matches_multiplication() {
        let a = nat_from_be(&h(concat!(
            "f3e0d9a54a0d7b25331f4d6bfd8fa506bfc51025dbe58e725d57d30aad4b45038e220bc4621b9439",
            "852083d9fca716c40a33acd51e6699f9823c118dc10e77452000000000000001ffffffffffffffff"
        )));
        let b = nat_from_be(&h("8000000000000000ffffffffffffffff0000000000000001"));
        let (q, r) = nat_divrem(&a, &b);
        assert_eq!(nat_cmp(&r, &b), Ordering::Less);
        assert_eq!(nat_add(&nat_mul(&q, &b), &r), a);
    }

    #[test]
    fn dh_ltp_vectors() {
        let (p, g, x) = (h(DH_PRIME), h(DH_BASE), h(DH_PRIV));
        assert_eq!(dh_secret_len(&g, &x, &p), Ok(256));
        let secret = dh_compute(&g, &x, &p).unwrap();
        assert_eq!(secret, h(DH_SECRET));
        assert_eq!(dh_kdf("sha256", &secret, b"LTP-KDF-TEST-INFO", 32).unwrap(), h(DH_KDF));
        // Longer output is further counter blocks; shorter is a prefix.
        let long = dh_kdf("sha256", &secret, b"LTP-KDF-TEST-INFO", 40).unwrap();
        assert_eq!(&long[..32], &h(DH_KDF)[..]);
        let mut c2 = 2u32.to_be_bytes().to_vec();
        c2.extend_from_slice(&secret);
        c2.extend_from_slice(b"LTP-KDF-TEST-INFO");
        assert_eq!(&long[32..], &hash("sha256", &[&c2]).unwrap()[..8]);
        assert_eq!(dh_kdf("sha256", &secret, b"x", 5).unwrap().len(), 5);
        assert_eq!(dh_kdf("sha9000", &secret, b"x", 32), None);
    }

    #[test]
    fn dh_errors() {
        let (p, g, x) = (h(DH_PRIME), h(DH_BASE), h(DH_PRIV));
        // A prime under 1536 bits.
        assert_eq!(dh_secret_len(&g[..100], &x, &p[..191]), Err(EINVAL));
        // A base or private key longer than the prime.
        let mut long = vec![0u8];
        long.extend_from_slice(&g);
        assert_eq!(dh_secret_len(&long, &x, &p), Err(EINVAL));
        // A zero prime.
        assert_eq!(dh_secret_len(&g, &x, &[0u8; 256]), Err(EINVAL));
        // Leading zeros count towards the prime's 1536 bits but not the
        // secret's length, which is rounded up to 8.
        let mut small = vec![0u8; 100];
        small.extend_from_slice(&p[..101]);
        assert_eq!(dh_secret_len(&[2], &[3], &small), Ok(104));
        assert_eq!(dh_compute(&[2], &[3], &small).unwrap(), {
            let mut v = vec![0u8; 103];
            v.push(8);
            v
        });
    }

    fn asym(hexdata: &str) -> Asym {
        parse_asymmetric(&h(hexdata)).unwrap()
    }

    #[test]
    fn certificate_descriptions() {
        let c = asym(CERT29);
        assert!(!c.private);
        assert_eq!(c.description, b"ltp-keyctl-pkey: 1969a70c58c5d7b30b26ce2a3465aea7adf6ab74");
        assert_eq!(c.fingerprint, h("1969a70c58c5d7b30b26ce2a3465aea7adf6ab74"));
        assert_eq!(c.key_bits, 2048);
        assert_eq!(c.sig_hash, "sha256");
        assert_eq!(
            asym(CERT23).description,
            b"ltp-keyctl23-untrusted: d38dd1e4774ee2b2b6ab3158697b2731ce00cd60"
        );
        let c05 = asym(CERT05);
        assert_eq!(
            c05.description,
            b"Internet Widgits Pty Ltd: 6f393a46df2963de547b6c3106d09f3616fb9cbf"
        );
        assert_eq!(c05.key_bits, 512);
        // CN prefixed by O gives the CN alone; a CN unlike the O gives both.
        assert_eq!(asym(CA).description, b"FWE Test CA: b62ae1a1706c92ba811ef2b7580f0bef0f7b5b65");
        assert_eq!(
            asym(LEAF).description,
            b"Example Org: leaf: 12f6570f00d3c7b6480045fb6c0f10c5d7dc6c48"
        );
        // Without a subject key identifier, the serial number as encoded.
        let bare = asym(BARE);
        assert_eq!(bare.description, b"Example Org: leaf: 00a1b2");
        assert_eq!(bare.sig_hash, "sha1");
    }

    #[test]
    fn pkcs8_key() {
        let k = asym(PKCS8);
        assert!(k.private);
        assert!(k.description.is_empty());
        assert_eq!(k.key_bits, 2048);
        assert_eq!(k.n, asym(CERT29).n);
    }

    #[test]
    fn parse_errors() {
        assert_eq!(parse_asymmetric(b""), Err(EINVAL));
        assert_eq!(parse_asymmetric(b"not a key at all"), Err(EBADMSG));
        let cert = h(CERT29);
        assert_eq!(parse_asymmetric(&cert[..cert.len() - 1]), Err(EBADMSG));
        // A self-signed certificate whose signature does not verify: over
        // other data, or not a signature at all.
        let mut bad = cert.clone();
        bad[16] ^= 1;
        assert_eq!(parse_asymmetric(&bad), Err(EKEYREJECTED));
        let mut bad = cert.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(parse_asymmetric(&bad), Err(EINVAL));
        // An unknown signature algorithm (sha256WithRSA made 1.1.99).
        let mut unknown = cert.clone();
        let oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
        let at = unknown.windows(9).position(|w| w == oid).unwrap();
        unknown[at + 8] = 99;
        assert_eq!(parse_asymmetric(&unknown), Err(ENOPKG));
        // Over 65535 bytes.
        let mut big = vec![0x30, 0x83, 0x01, 0x00, 0x00];
        big.resize(0x10005, 0);
        assert_eq!(parse_asymmetric(&big), Err(EMSGSIZE));
        // A PKCS#8 key of another algorithm.
        let mut p8 = h(PKCS8);
        let rsa = p8.windows(9).position(|w| w == OID_RSA).unwrap();
        p8[rsa + 8] = 2;
        assert_eq!(parse_asymmetric(&p8), Err(ENOPKG));
    }

    #[test]
    fn pkey_query_ltp() {
        let cert = asym(CERT29);
        let q = pkey_query(&cert, "enc=pkcs1").unwrap();
        assert_eq!(
            q,
            PkeyQuery {
                supported_ops: KEYCTL_SUPPORTS_ENCRYPT | KEYCTL_SUPPORTS_VERIFY,
                key_size: 2048,
                max_data_size: 256,
                max_sig_size: 256,
                max_enc_size: 256,
                max_dec_size: 256,
            }
        );
        let key = asym(PKCS8);
        let q = pkey_query(&key, "enc=pkcs1").unwrap();
        assert_eq!(q.supported_ops, 0xf);
        assert_eq!((q.key_size, q.max_dec_size, q.max_sig_size), (2048, 256, 256));
        // Raw RSA has no signature operations.
        assert_eq!(pkey_query(&cert, "").unwrap().supported_ops, 1);
        assert_eq!(pkey_query(&key, "enc=raw").unwrap().supported_ops, 3);
        assert_eq!(pkey_query(&key, " enc=pkcs1\thash=sha256 ").unwrap().supported_ops, 0xf);
        assert_eq!(pkey_query(&key, "enc=pkcs1 bogus=1"), Err(EINVAL));
        assert_eq!(pkey_query(&key, "enc=pkcs1 enc=pkcs1"), Err(EINVAL));
        assert_eq!(pkey_query(&key, "enc="), Err(EINVAL));
        assert_eq!(pkey_query(&key, "enc=oaep"), Err(EINVAL));
        assert_eq!(pkey_query(&key, "enc=raw hash=sha256"), Err(EINVAL));
        assert_eq!(pkey_query(&key, "enc=pkcs1 hash=sha9000"), Err(ENOENT));
    }

    #[test]
    fn pkey_sign_and_verify() {
        let cert = asym(CERT29);
        let key = asym(PKCS8);
        let digest = h(FWE_DIGEST);
        let info = "enc=pkcs1 hash=sha256";
        let sig = pkey_sign(&key, info, &digest, 256).unwrap();
        assert_eq!(sig, h(FWE_SIG));
        assert_eq!(pkey_verify(&cert, info, &digest, &sig), Ok(()));
        assert_eq!(pkey_verify(&key, info, &digest, &sig), Ok(()));
        let mut wrong = digest.clone();
        wrong[0] ^= 1;
        assert_eq!(pkey_verify(&cert, info, &wrong, &sig), Err(EKEYREJECTED));
        assert_eq!(pkey_verify(&cert, info, &digest[..20], &sig), Err(EKEYREJECTED));
        assert_eq!(pkey_verify(&cert, "enc=pkcs1 hash=sha1", &digest, &sig), Err(EBADMSG));
        assert_eq!(pkey_verify(&cert, info, &digest, &sig[1..]), Err(EINVAL));
        assert_eq!(pkey_verify(&cert, "enc=raw", &digest, &sig), Err(ENOSYS));
        // Without a hash, the DigestInfo is part of the data.
        let di = [pkcs1_digest_info("sha256").unwrap(), &digest].concat();
        assert_eq!(pkey_sign(&key, "enc=pkcs1", &di, 256).unwrap(), sig);
        assert_eq!(pkey_verify(&cert, "enc=pkcs1", &di, &sig), Ok(()));
        // A public key cannot sign; raw RSA does not sign.
        assert_eq!(pkey_sign(&cert, info, &digest, 256), Err(EINVAL));
        assert_eq!(pkey_sign(&key, "enc=raw", &digest, 256), Err(EINVAL));
        // A short output buffer, and input over the limits.
        assert_eq!(pkey_sign(&key, info, &digest, 255), Err(EOVERFLOW));
        assert_eq!(pkey_sign(&key, info, &[0; 257], 256), Err(EINVAL));
        assert_eq!(pkey_sign(&key, info, &[0; 240], 256), Err(EOVERFLOW));
    }

    #[test]
    fn pkey_encrypt_and_decrypt() {
        let cert = asym(CERT29);
        let key = asym(PKCS8);
        let mut counter = 0u8;
        let mut random = |buf: &mut [u8]| {
            for b in buf {
                counter = counter.wrapping_add(37);
                *b = counter;
            }
        };
        let msg = b"a secret message";
        let ct = pkey_encrypt(&cert, "enc=pkcs1", msg, 256, &mut random).unwrap();
        assert_eq!(ct.len(), 256);
        let pt = pkey_decrypt(&key, "enc=pkcs1", &ct, 256).unwrap();
        assert_eq!(pt, msg);
        assert_eq!(pkey_decrypt(&key, "enc=pkcs1", &ct, 4), Err(EOVERFLOW));
        assert_eq!(pkey_decrypt(&key, "enc=pkcs1", &ct[1..], 256), Err(EINVAL));
        assert_eq!(pkey_decrypt(&cert, "enc=pkcs1", &ct, 256), Err(EINVAL));
        assert_eq!(pkey_encrypt(&cert, "enc=pkcs1", &[1; 246], 256, &mut random), Err(EOVERFLOW));
        assert_eq!(pkey_encrypt(&cert, "enc=pkcs1", msg, 300, &mut random), Err(EINVAL));
        // Raw RSA: the integer itself, which must lie in 1 < m < n - 1.
        let mut m = vec![0u8; 256];
        m[255] = 42;
        let ct = pkey_encrypt(&cert, "enc=raw", &m, 256, &mut random).unwrap();
        assert_eq!(pkey_decrypt(&key, "enc=raw", &ct, 256).unwrap(), m);
        assert_eq!(pkey_encrypt(&cert, "enc=raw", &[1], 256, &mut random), Err(EINVAL));
    }

    #[test]
    fn restriction_signatures() {
        let ca = asym(CA);
        let leaf = asym(LEAF);
        let bare = asym(BARE);
        let other = asym(CERT29);
        // Matched by authority key identifier, and by issuer name.
        assert_eq!(verify_signed_by(&leaf, &ca), Ok(()));
        assert_eq!(verify_signed_by(&bare, &ca), Ok(()));
        assert_eq!(verify_signed_by(&ca, &ca), Ok(()));
        assert!(keyring_signer_matches(&leaf, &ca));
        assert!(keyring_signer_accepted(&leaf, &ca));
        assert!(keyring_signer_matches(&bare, &ca));
        assert!(!keyring_signer_matches(&leaf, &other));
        assert_eq!(verify_signed_by(&leaf, &other), Err(ENOKEY));
        assert_eq!(verify_signed_by(&leaf, &leaf), Err(ENOKEY));
        // A signature that does not verify.
        let mut forged = leaf.clone();
        forged.tbs[20] ^= 1;
        assert_eq!(verify_signed_by(&forged, &ca), Err(EKEYREJECTED));
        // The matching identifiers of another key.
        let mut impostor = other.clone();
        impostor.skid = ca.skid.clone();
        assert_eq!(verify_signed_by(&leaf, &impostor), Err(EINVAL));
        // A private key has no signature to check, nor identifiers.
        let key = asym(PKCS8);
        assert_eq!(verify_signed_by(&key, &ca), Err(ENOPKG));
        assert_eq!(verify_signed_by(&leaf, &key), Err(ENOKEY));
    }

    #[test]
    fn asym_encoding_round_trip() {
        for c in [CERT29, PKCS8, LEAF, BARE] {
            let a = asym(c);
            assert_eq!(Asym::decode(&a.encode()), Some(a.clone()));
            let enc = a.encode();
            assert_eq!(Asym::decode(&enc[..enc.len() - 1]), None);
        }
        let mut a = asym(LEAF);
        a.akid_serial = Some(vec![1, 2]);
        a.akid_issuer = Some(vec![]);
        assert_eq!(Asym::decode(&a.encode()), Some(a));
    }

    fn masters(desc: &[u8]) -> Option<Vec<u8>> {
        match desc {
            b"user:masterkey" => Some(b"foo".to_vec()),
            b"user:other" => Some(b"a longer master key, over 32 bytes long".to_vec()),
            _ => None,
        }
    }

    fn fill(buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8 ^ 0x5a;
        }
    }

    const ENC32_VALID: &[u8] = b"new enc32 user:masterkey 32 abcdefABCDEF1234567890aaaaaaaaaaabcdefABCDEF1234567890aaaaaaaaaa";
    const ENC32_INVALID: &[u8] = b"new enc32 user:masterkey 32 plaintext123@123!123@123!123@123plaintext123@123!123@123!123@123";

    #[test]
    fn encrypted_key_ltp_keyctl09() {
        let k =
            EncryptedKey::instantiate(b"ltptestkey1", ENC32_VALID, &masters, &mut fill).unwrap();
        assert_eq!(k.decrypted, h(&String::from_utf8_lossy(&ENC32_VALID[28..])));
        assert_eq!(k.format, b"enc32");
        // Larger than LTP's 128-byte buffer: KEYCTL_READ returns the size.
        assert_eq!(k.read_len(), 186);
        assert_eq!(k.read(&masters).unwrap().len(), 186);
        assert_eq!(
            EncryptedKey::instantiate(b"ltptestkey2", ENC32_INVALID, &masters, &mut fill),
            Err(EINVAL)
        );
    }

    #[test]
    fn encrypted_key_round_trip() {
        let k =
            EncryptedKey::instantiate(b"k", b"new user:masterkey 32", &masters, &mut fill).unwrap();
        assert_eq!(k.format, b"default");
        assert_eq!(k.decrypted.len(), 32);
        let read = k.read(&masters).unwrap();
        let text = String::from_utf8(read.clone()).unwrap();
        let fields: Vec<&str> = text.split(' ').collect();
        assert_eq!(&fields[..3], &["default", "user:masterkey", "32"]);
        assert_eq!(fields[3].len(), (16 + 1 + 32 + 32) * 2);
        assert_eq!(&fields[3][..32], hex(&k.iv));
        assert_eq!(&fields[3][32..34], "00");
        // The encrypted data is AES-256-CBC under the derived key.
        let mut enc_buf = b"ENC_KEY\0foo".to_vec();
        enc_buf.resize(32, 0);
        let enc_key = hash("sha256", &[&enc_buf]).unwrap();
        let enc = aes_cbc_encrypt(&enc_key, &k.iv, &k.decrypted).unwrap();
        assert_eq!(&fields[3][34..34 + 64], hex(&enc));
        assert_eq!(k.read_len(), read.len());
        assert_eq!(k.quota_len(), 32 + 7 + 1 + 14 + 1 + 2 + 1 + 16 + 1 + 32 + 32 + 1);

        // Loading the read form gives the same key.
        let load = [b"load ".as_slice(), &read].concat();
        let l = EncryptedKey::instantiate(b"k2", &load, &masters, &mut |_| panic!()).unwrap();
        assert_eq!(l, k);
        // Without the format the HMAC covers less and does not match.
        let noformat = [b"load ".as_slice(), &read[8..]].concat();
        assert_eq!(EncryptedKey::instantiate(b"k2", &noformat, &masters, &mut fill), Err(EINVAL));
        // A tampered HMAC, a missing master key, a malformed blob.
        let mut bad = load.clone();
        let last = bad.len() - 1;
        bad[last] = if bad[last] == b'0' { b'1' } else { b'0' };
        assert_eq!(EncryptedKey::instantiate(b"k2", &bad, &masters, &mut fill), Err(EINVAL));
        let missing = String::from_utf8(load.clone()).unwrap().replace("masterkey", "nokey");
        assert_eq!(
            EncryptedKey::instantiate(b"k2", missing.as_bytes(), &masters, &mut fill),
            Err(ENOKEY)
        );
        assert_eq!(
            EncryptedKey::instantiate(b"k2", &load[..load.len() - 2], &masters, &mut fill),
            Err(EINVAL)
        );

        // Updating changes the master key the next read uses.
        let u = k.update(b"update user:other").unwrap();
        assert_eq!(u.master_desc, b"user:other");
        assert_eq!(u.decrypted, k.decrypted);
        let reread = u.read(&masters).unwrap();
        assert!(reread.starts_with(b"default user:other 32 "));
        let reload = [b"load ".as_slice(), &reread].concat();
        let l2 = EncryptedKey::instantiate(b"k3", &reload, &masters, &mut fill).unwrap();
        assert_eq!(l2.decrypted, k.decrypted);
        assert_eq!(k.update(b"update trusted:x"), Err(EINVAL));
        assert_eq!(k.update(b"new user:x 32"), Err(EINVAL));
        assert_eq!(k.update(b""), Err(EINVAL));
    }

    #[test]
    fn encrypted_key_errors() {
        let new = |desc: &[u8], p: &[u8]| EncryptedKey::instantiate(desc, p, &masters, &mut fill);
        assert_eq!(new(b"k", b"").err(), Some(EINVAL));
        assert_eq!(new(b"k", b"new").err(), Some(EINVAL));
        assert_eq!(new(b"k", b"new user:masterkey").err(), Some(EINVAL));
        assert_eq!(new(b"k", b"new  user:masterkey 32").err(), Some(EINVAL));
        assert_eq!(new(b"k", b"new user: 32").err(), Some(EINVAL));
        assert_eq!(new(b"k", b"new logon:masterkey 32").err(), Some(EINVAL));
        assert_eq!(new(b"k", b"new user:masterkey 19").err(), Some(EINVAL));
        assert_eq!(new(b"k", b"new user:masterkey 4097").err(), Some(EINVAL));
        assert_eq!(new(b"k", b"new user:masterkey 0x20").err(), Some(EINVAL));
        assert_eq!(new(b"k", b"new user:masterkey 32 ").err(), Some(EINVAL));
        assert_eq!(new(b"k", b"bogus user:masterkey 32").err(), Some(EINVAL));
        assert_eq!(new(b"k", b"update user:masterkey").err(), Some(EINVAL));
        assert_eq!(new(b"k", b"new enc32 user:masterkey 33").err(), Some(EINVAL));
        // ecryptfs wants 64 bytes and a 16-hex-digit description.
        assert_eq!(new(b"0123456789abcdef", b"new ecryptfs user:masterkey 32").err(), Some(EINVAL));
        assert_eq!(new(b"not-hex-desc!!!!", b"new ecryptfs user:masterkey 64").err(), Some(EINVAL));
        let e = new(b"0123456789abcdef", b"new ecryptfs user:masterkey 64").unwrap();
        assert_eq!(e.quota_len(), 737 + 8 + 1 + 14 + 1 + 2 + 1 + 16 + 1 + 64 + 32 + 1);
        // A trusted master key can be named but not used.
        let t = new(b"k", b"new trusted:tk 32").unwrap();
        assert_eq!(t.read(&masters), Err(EOPNOTSUPP));
        // Accepted variants of the length.
        assert!(new(b"k", b"new user:masterkey +32").is_ok());
        assert!(new(b"k", b"new user:masterkey 32\n").is_ok());
        assert!(new(b"k", b"new default user:masterkey 32\0ignored").is_ok());
    }
}
