// Copyright 2023 Ulvetanna Inc.

use ark_std::{end_timer, start_timer};
use bytesize::ByteSize;
use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_challenger::{
	CanObserve, DuplexChallenger, FieldChallenger, HashChallenger, SerializingChallenger32,
};
use p3_commit::{ExtensionMmcs, Pcs, PolynomialSpace};
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, ExtensionField, Field};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{
	CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher32, TruncatedPermutation,
};
use rand::{
	distributions::{Distribution, Standard},
	thread_rng, Rng,
};

fn run_commit_prove_verify_fri_pcs<Val, Challenge, Challenger, P, R>(
	pcs: P,
	challenger: Challenger,
	log_degree: usize,
	log_batch_size: usize,
	mut rng: R,
) where
	P: Pcs<Challenge, Challenger>,
	P::Domain: PolynomialSpace<Val = Val>,
	Val: Field,
	Standard: Distribution<Val>,
	Challenge: ExtensionField<Val>,
	Challenger: Clone + CanObserve<P::Commitment> + FieldChallenger<Val>,
	R: Rng,
{
	let mut p_challenger = challenger.clone();

	let degree = 1 << log_degree;
	let batch_size = 1 << log_batch_size;
	let domain = pcs.natural_domain_for_degree(degree);

	let gen_timer = start_timer!(|| "gen_data");
	let matrix = RowMajorMatrix::<Val>::rand(&mut rng, degree, batch_size);
	end_timer!(gen_timer);

	let commit_timer = start_timer!(|| "commit");
	let (commitment, committed) = pcs.commit(vec![(domain, matrix)]);
	end_timer!(commit_timer);

	p_challenger.observe(commitment.clone());

	let zeta: Challenge = p_challenger.sample_ext_element();

	let prove_timer = start_timer!(|| "prove");
	let (opening_by_round, proof) =
		pcs.open(vec![(&committed, vec![vec![zeta]])], &mut p_challenger);
	end_timer!(prove_timer);

	assert_eq!(opening_by_round.len(), 1);
	let point_openings = opening_by_round[0][0][0].clone();

	// Verify the proof.
	let mut v_challenger = challenger.clone();
	v_challenger.observe(commitment.clone());
	let verifier_zeta: Challenge = v_challenger.sample_ext_element();
	assert_eq!(verifier_zeta, zeta);

	let verify_timer = start_timer!(|| "verify");
	pcs.verify(
		vec![(commitment, vec![(domain, vec![(zeta, point_openings)])])],
		&proof,
		&mut v_challenger,
	)
	.unwrap();
	end_timer!(verify_timer);

	let proof_size = bincode::serialized_size(&proof).unwrap();
	println!("Proof size = {}", ByteSize(proof_size));

	println!();
}

fn profile_commit_prove_verify_fri_pcs_poseidon2(
	log_degree: usize,
	log_batch_size: usize,
	log_inv_rate: usize,
) {
	type Val = BabyBear;
	type Challenge = BinomialExtensionField<Val, 4>;

	type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
	type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
	type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

	type ValMmcs =
		MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 8>;
	type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

	type Dft = Radix2DitParallel<Val>;
	type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
	type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

	let mut rng = thread_rng();

	let perm = Perm::new_from_rng_128(
		Poseidon2ExternalMatrixGeneral,
		DiffusionMatrixBabyBear::default(),
		&mut rng,
	);
	let hash = MyHash::new(perm.clone());
	let compress = MyCompress::new(perm.clone());

	let val_mmcs = ValMmcs::new(hash, compress);
	let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

	let fri_config = FriConfig {
		log_blowup: log_inv_rate,
		num_queries: 100,
		proof_of_work_bits: 0,
		mmcs: challenge_mmcs,
	};

	let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_config);
	let challenger = Challenger::new(perm.clone());

	println!("plonky3 with poseidon2 merkle log_coeffs={}", log_degree + log_batch_size);
	run_commit_prove_verify_fri_pcs(pcs, challenger, log_degree, log_batch_size, rng);
}

fn profile_commit_prove_verify_fri_pcs_keccak(
	log_degree: usize,
	log_batch_size: usize,
	log_inv_rate: usize,
) {
	type Val = BabyBear;
	type Challenge = BinomialExtensionField<Val, 4>;

	type ByteHash = Keccak256Hash;
	type MyHash = SerializingHasher32<ByteHash>;
	type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;

	type ValMmcs = MerkleTreeMmcs<Val, u8, MyHash, MyCompress, 32>;
	type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

	type Dft = Radix2DitParallel<Val>;
	type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
	type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

	let byte_hash = ByteHash {};
	let hash = MyHash::new(Keccak256Hash {});
	let compress = MyCompress::new(byte_hash);

	let val_mmcs = ValMmcs::new(hash, compress);
	let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

	let fri_config = FriConfig {
		log_blowup: log_inv_rate,
		num_queries: 142,
		proof_of_work_bits: 0,
		mmcs: challenge_mmcs,
	};

	let rng = thread_rng();
	let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_config);
	let challenger = Challenger::from_hasher(vec![], byte_hash);

	println!("plonky3 with keccak merkle log_coeffs={}", log_degree + log_batch_size);
	run_commit_prove_verify_fri_pcs(pcs, challenger, log_degree, log_batch_size, rng);
}

fn main() {
	let log_batch_size = 4;
	let log_inv_rate = 2;
	for log_degree in [20, 24, 28] {
		profile_commit_prove_verify_fri_pcs_poseidon2(
			log_degree - log_batch_size,
			log_batch_size,
			log_inv_rate,
		);
		profile_commit_prove_verify_fri_pcs_keccak(
			log_degree - log_batch_size,
			log_batch_size,
			log_inv_rate,
		);
	}
}
