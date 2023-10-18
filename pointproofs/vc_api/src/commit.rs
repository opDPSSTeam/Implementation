use super::util;
use ark_bls12_381::Bls12_381;



use pointproof::Commitment;
use pointproof::CommitmentScheme;
use pointproof::ProverParam;
use pointproof::StructuredReferenceString;
use pointproof::VerifierParam;

pub fn gen_params<const N: usize>() -> String {
    let mut rng = rand::thread_rng();
    let srs = StructuredReferenceString::<Bls12_381, N>::new_srs_for_testing(&mut rng);
    util::srs_to_str(srs)
}

pub fn commit<const N: usize>(srs: &str, messages: &str) -> String {
    let srs = util::str_to_srs(srs);
    let prover_param: ProverParam<Bls12_381, N> = (&srs).into();
    let messages = util::str_to_messages(messages);
    let commitment = Commitment::<Bls12_381, N>::commit(&prover_param, &messages)
        .commitment
        .into();
    util::g1_to_str(commitment)
}

pub fn open<const N: usize>(srs: &str, messages: &str, pos: usize) -> String {
    let srs = util::str_to_srs(srs);
    let prover_param: ProverParam<Bls12_381, N> = (&srs).into();
    let messages = util::str_to_messages(messages);
    let witness = Commitment::<Bls12_381, N>::open(&prover_param, &messages, pos).into();
    util::g1_to_str(witness)
}

pub fn verify<const N: usize>(
    srs: &str,
    commitment: &str,
    message: &str,
    pos: usize,
    witness: &str,
) -> bool {
    let srs = util::str_to_srs(srs);
    let commitment = Commitment {
        commitment: util::str_to_g1(commitment).into(),
    };
    let message = util::str_to_message(message);
    let witness = util::str_to_g1(witness);

    let verifier_param: VerifierParam<Bls12_381, N> = (&srs).into();
    commitment.verify(&verifier_param, &message, pos, &witness.into())
}
