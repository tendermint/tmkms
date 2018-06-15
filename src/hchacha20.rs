#![allow(dead_code)]

use byteorder::{ByteOrder, LE};

/// Output size of the HChaCha20 function in bytes
const OUTPUT_SIZE: usize = 32;

macro_rules! quarter_round {
    ($state:ident, $idx0:expr, $idx1:expr, $idx2:expr, $idx3:expr) => {
        let mut a = $state[0 + $idx0];
        let mut b = $state[4 + $idx1];
        let mut c = $state[8 + $idx2];
        let mut d = $state[12 + $idx3];

        a = a.wrapping_add(b);
        d = (d ^ a).rotate_left(16);

        c = c.wrapping_add(d);
        b = (b ^ c).rotate_left(12);

        a = a.wrapping_add(b);
        d = (d ^ a).rotate_left(8);

        c = c.wrapping_add(d);
        b = (b ^ c).rotate_left(7);

        $state[0 + $idx0] = a;
        $state[4 + $idx1] = b;
        $state[8 + $idx2] = c;
        $state[12 + $idx3] = d;
    };
}

/// The HChaCha20 function: adapts the ChaCha20 core function in the same
/// manner that HSalsa20 adapts the Salsa20 function.
///
/// HChaCha20 takes 512-bits of input:
///
/// * Constants (`u32` x 4)
/// * Key (`u32` x 8)
/// * Nonce (`u32` x 4)
///
/// It produces 256-bits of output suitable for use as a ChaCha20 key
///
/// For more information on HSalsa20 on which HChaCha20 is based, see:
///
/// <http://cr.yp.to/snuffle/xsalsa-20110204.pdf>
///
pub fn hchacha20(key: &[u8; 32], input: &[u8; 16]) -> [u8; OUTPUT_SIZE] {
    let mut state = [0u32; 16];

    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;

    for i in 0..8 {
        state[4 + i] = LE::read_u32(&key[(i * 4)..((i + 1) * 4)]);
    }

    for i in 0..4 {
        state[12 + i] = LE::read_u32(&input[(i * 4)..((i + 1) * 4)]);
    }

    // 20 rounds consisting of 10 column rounds and 10 diagonal rounds
    for _ in 0..10 {
        // column rounds
        quarter_round!(state, 0, 0, 0, 0);
        quarter_round!(state, 1, 1, 1, 1);
        quarter_round!(state, 2, 2, 2, 2);
        quarter_round!(state, 3, 3, 3, 3);

        // diagonal rounds
        quarter_round!(state, 0, 1, 2, 3);
        quarter_round!(state, 1, 2, 3, 0);
        quarter_round!(state, 2, 3, 0, 1);
        quarter_round!(state, 3, 0, 1, 2);
    }

    let mut out = [0u8; OUTPUT_SIZE];

    for i in 0..4 {
        LE::write_u32(&mut out[(i * 4)..((i + 1) * 4)], state[i]);
    }

    for i in 4..8 {
        LE::write_u32(&mut out[(i * 4)..((i + 1) * 4)], state[i + 8]);
    }

    out
}

/// Test against vectors from:
/// https://tools.ietf.org/id/draft-paragon-paseto-rfc-00.html#rfc.section.7.2.1
#[cfg(test)]
mod tests {
    use super::hchacha20;

    const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    const INPUT: [u8; 16] = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59,
        0x27,
    ];

    const OUTPUT: [u8; 32] = [
        0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0xe, 0x42, 0x50, 0x8a, 0x87, 0x7d,
        0x73, 0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13, 0x26, 0xd3,
        0xec, 0xdc,
    ];

    #[test]
    fn test_vectors() {
        let actual = hchacha20(&KEY, &INPUT);
        assert_eq!(actual, OUTPUT);
    }
}
