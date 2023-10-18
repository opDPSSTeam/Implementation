use ark_bls12_381::Bls12_381;
use ark_bls12_381::{Fq2Parameters, Fq6Parameters, Fr};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::PairingEngine;
use ark_ff::BigInteger384;
use ark_ff::QuadExtField;
use ark_ff::{BigInteger, BigInteger256};
use ark_ff::{CubicExtField, Fp2ParamsWrapper, Fp6ParamsWrapper};
use base64::{decode, encode};
use pointproof::StructuredReferenceString;

pub fn convert_bits_to_bytes(mut bits: Vec<bool>) -> Vec<u8> {
    while bits.len() % 8 != 0 {
        bits.push(false);
    }
    let mut res = vec![];
    for i in (0..bits.len()).step_by(8) {
        let mut x = 0;
        for j in (0..8).rev() {
            x = (x << 1) | (bits[i + j] as u8);
        }
        res.push(x);
    }
    res
}

pub fn convert_bytes_to_bits(bytes: &Vec<u8>) -> Vec<bool> {
    let mut res = vec![];
    for i in 0..bytes.len() {
        let mut x = bytes[i];
        for _j in 0..8 {
            res.push(x % 2 == 1);
            x >>= 1;
        }
    }
    res
}

pub fn bytes_to_g1(bytes: [Vec<u8>; 3]) -> <Bls12_381 as PairingEngine>::G1Affine {
    let x = BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[0]));
    let y = BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[1]));
    let infinity = convert_bytes_to_bits(&bytes[2])[0];
    GroupAffine::new(x.into(), y.into(), infinity)
}

pub fn g1_to_bytes(g1: <Bls12_381 as PairingEngine>::G1Affine) -> [Vec<u8>; 3] {
    let int_x: BigInteger384 = g1.x.into();
    let x = convert_bits_to_bytes(int_x.to_bits_le());
    let int_y: BigInteger384 = g1.y.into();
    let y = convert_bits_to_bytes(int_y.to_bits_le());
    let infinity = convert_bits_to_bytes(vec![g1.infinity]);
    [x, y, infinity]
}

pub fn g1_to_str(g1: <Bls12_381 as PairingEngine>::G1Affine) -> String {
    let bytes = g1_to_bytes(g1);
    let mut res = String::new();
    for i in bytes {
        res.push_str(&encode(i));
        res.push(',');
    }
    res
}

pub fn str_to_g1(s: &str) -> <Bls12_381 as PairingEngine>::G1Affine {
    let bytes = s
        .split(",")
        .filter(|&x| x.len() > 0)
        .map(|x| decode(x).unwrap())
        .collect::<Vec<Vec<u8>>>()
        .try_into()
        .unwrap();
    bytes_to_g1(bytes)
}

pub fn bytes_to_g2(bytes: [Vec<u8>; 5]) -> <Bls12_381 as PairingEngine>::G2Affine {
    GroupAffine::new(
        QuadExtField::<Fp2ParamsWrapper<Fq2Parameters>>::new(
            BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[0])).into(),
            BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[1])).into(),
        ),
        QuadExtField::<Fp2ParamsWrapper<Fq2Parameters>>::new(
            BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[2])).into(),
            BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[3])).into(),
        ),
        convert_bytes_to_bits(&bytes[4])[0],
    )
}

pub fn g2_to_bytes(g2: <Bls12_381 as PairingEngine>::G2Affine) -> [Vec<u8>; 5] {
    let mut res = vec![];
    let quad_ext_field = g2.x;
    let i: BigInteger384 = quad_ext_field.c0.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));
    let i: BigInteger384 = quad_ext_field.c1.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));

    let quad_ext_field = g2.y;
    let i: BigInteger384 = quad_ext_field.c0.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));
    let i: BigInteger384 = quad_ext_field.c1.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));

    let infinity = convert_bits_to_bytes(vec![g2.infinity]);
    res.push(infinity);

    res.try_into().unwrap()
}

pub fn bytes_to_quad_ext_field(bytes: [Vec<u8>; 12]) -> <Bls12_381 as PairingEngine>::Fqk {
    <Bls12_381 as PairingEngine>::Fqk::new(
        CubicExtField::<Fp6ParamsWrapper<Fq6Parameters>>::new(
            QuadExtField::<Fp2ParamsWrapper<Fq2Parameters>>::new(
                BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[0])).into(),
                BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[1])).into(),
            ),
            QuadExtField::<Fp2ParamsWrapper<Fq2Parameters>>::new(
                BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[2])).into(),
                BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[3])).into(),
            ),
            QuadExtField::<Fp2ParamsWrapper<Fq2Parameters>>::new(
                BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[4])).into(),
                BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[5])).into(),
            ),
        ),
        CubicExtField::<Fp6ParamsWrapper<Fq6Parameters>>::new(
            QuadExtField::<Fp2ParamsWrapper<Fq2Parameters>>::new(
                BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[6])).into(),
                BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[7])).into(),
            ),
            QuadExtField::<Fp2ParamsWrapper<Fq2Parameters>>::new(
                BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[8])).into(),
                BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[9])).into(),
            ),
            QuadExtField::<Fp2ParamsWrapper<Fq2Parameters>>::new(
                BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[10])).into(),
                BigInteger384::from_bits_le(&convert_bytes_to_bits(&bytes[11])).into(),
            ),
        ),
    )
}

pub fn quad_ext_field_to_bytes(t: <Bls12_381 as PairingEngine>::Fqk) -> [Vec<u8>; 12] {
    let mut res = vec![];
    let cubic_ext_field = t.c0;

    let quad_ext_field = cubic_ext_field.c0;
    let i: BigInteger384 = quad_ext_field.c0.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));
    let i: BigInteger384 = quad_ext_field.c1.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));

    let quad_ext_field = cubic_ext_field.c1;
    let i: BigInteger384 = quad_ext_field.c0.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));
    let i: BigInteger384 = quad_ext_field.c1.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));

    let quad_ext_field = cubic_ext_field.c2;
    let i: BigInteger384 = quad_ext_field.c0.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));
    let i: BigInteger384 = quad_ext_field.c1.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));

    let cubic_ext_field = t.c1;

    let quad_ext_field = cubic_ext_field.c0;
    let i: BigInteger384 = quad_ext_field.c0.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));
    let i: BigInteger384 = quad_ext_field.c1.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));

    let quad_ext_field = cubic_ext_field.c1;
    let i: BigInteger384 = quad_ext_field.c0.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));
    let i: BigInteger384 = quad_ext_field.c1.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));

    let quad_ext_field = cubic_ext_field.c2;
    let i: BigInteger384 = quad_ext_field.c0.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));
    let i: BigInteger384 = quad_ext_field.c1.into();
    res.push(convert_bits_to_bytes(i.to_bits_le()));

    res.try_into().unwrap()
}

pub fn str_to_message(s: &str) -> Fr {
    let bytes = decode(s).unwrap();
    let bits = convert_bytes_to_bits(&bytes);
    BigInteger256::from_bits_le(&bits).into()
}

pub fn message_to_str(message: Fr) -> String {
    let bint: BigInteger256 = message.into();
    let bits = bint.to_bits_le();
    let bytes = convert_bits_to_bytes(bits);
    encode(bytes)
}

pub fn str_to_messages(s: &str) -> Vec<Fr> {
    s.split(';')
        .filter(|&x| x.len() > 0)
        .map(|x| str_to_message(x))
        .collect()
}

pub fn messages_to_str(messages: Vec<Fr>) -> String {
    let mut res = String::new();
    for i in messages {
        res.push_str(&message_to_str(i));
        res.push(';');
    }
    res
}

pub fn str_to_srs<const N: usize>(s: &str) -> StructuredReferenceString<Bls12_381, N> {
    let strings = s.split_ascii_whitespace().collect::<Vec<&str>>();
    assert_eq!(strings.len(), 3);
    let g_str = strings[0]
        .split(";")
        .filter(|&x| x.len() > 0)
        .collect::<Vec<&str>>();
    let mut g = vec![];
    for i in g_str {
        g.push(str_to_g1(i));
    }

    let h_str = strings[1]
        .split(";")
        .filter(|&x| x.len() > 0)
        .collect::<Vec<&str>>();
    let mut h = vec![];
    for i in h_str {
        let bytes = i
            .split(",")
            .filter(|&x| x.len() > 0)
            .map(|x| decode(x).unwrap())
            .collect::<Vec<Vec<u8>>>()
            .try_into()
            .unwrap();
        h.push(bytes_to_g2(bytes));
    }
    let t_bytes = strings[2]
        .split(",")
        .filter(|&x| x.len() > 0)
        .map(|x| decode(x).unwrap())
        .collect::<Vec<Vec<u8>>>()
        .try_into()
        .unwrap();
    StructuredReferenceString {
        g,
        h,
        t: bytes_to_quad_ext_field(t_bytes),
    }
}

pub fn srs_to_str<const N: usize>(srs: StructuredReferenceString<Bls12_381, N>) -> String {
    let mut res = String::new();
    for i in srs.g {
        res.push_str(&g1_to_str(i));
        res.push(';');
    }
    res.push('\n');
    for i in srs.h {
        let bytes = g2_to_bytes(i);
        for j in bytes {
            res.push_str(encode(j).as_str());
            res.push(',');
        }
        res.push(';');
    }
    res.push('\n');
    for j in quad_ext_field_to_bytes(srs.t) {
        res.push_str(encode(j).as_str());
        res.push(',');
    }
    res
}
