// Copyright 2023 Ulvetanna Inc.

//! Run and measure timing of plonky2 FRI polynomial commitment scheme on batches of polynomials.

use ark_std::{end_timer, start_timer};
use bytesize::ByteSize;
use plonky2::{
	field::{
		fft::fft_root_table, goldilocks_field::GoldilocksField, polynomial::PolynomialValues,
		types::Field,
	},
	fri::{
		oracle::PolynomialBatch,
		structure::{
			FriBatchInfo, FriInstanceInfo, FriOpeningBatch, FriOpenings, FriOracleInfo,
			FriPolynomialInfo,
		},
		verifier::verify_fri_proof,
	},
	iop::challenger::Challenger,
	plonk::config::{GenericConfig, KeccakGoldilocksConfig, PoseidonGoldilocksConfig},
	util::timing::TimingTree,
};
use rand::{thread_rng, Rng};
use starky::config::StarkConfig;
use std::{any::type_name, iter::repeat_with};

fn profile_commit_prove_verify<C: GenericConfig<2, F = GoldilocksField>>(
	degree_bits: usize,
	n_bits: usize,
	batch_size: usize,
	print_proof_size: bool,
) {
	let mut fri_config = StarkConfig::standard_fast_config().fri_config;
	fri_config.cap_height = 0;

	let fri_params = fri_config.fri_params(degree_bits, false);

	let n_vals = 1 << degree_bits;
	let root_table = fft_root_table(n_vals << fri_config.rate_bits);

	let mut rng = thread_rng();

	println!(
		"config={}, degree_bits={}, n_bits={}, batch_size={}, rate_bits={}",
		type_name::<C>(),
		degree_bits,
		n_bits,
		batch_size,
		fri_config.rate_bits
	);

	let gen_timer = start_timer!(|| "gen data");
	let poly_values = repeat_with(|| {
		PolynomialValues::new(
			repeat_with(|| {
				if n_bits == 64 {
					GoldilocksField::from_noncanonical_u64(rng.gen())
				} else {
					GoldilocksField::from_noncanonical_u64(rng.gen_range(0..(1u64 << n_bits)))
				}
			})
			.take(n_vals)
			.collect(),
		)
	})
	.take(batch_size)
	.collect::<Vec<_>>();
	end_timer!(gen_timer);

	let commit_timer = start_timer!(|| "commit");
	let mut timing_tree = TimingTree::default();
	let committed = PolynomialBatch::<_, C, 2>::from_values(
		poly_values,
		fri_config.rate_bits,
		false,
		fri_config.cap_height,
		&mut timing_tree,
		Some(&root_table),
	);
	end_timer!(commit_timer);

	let mut challenger = Challenger::<GoldilocksField, C::Hasher>::new();
	challenger.observe_cap::<C::Hasher>(&committed.merkle_tree.cap);

	let zeta = challenger.get_extension_challenge::<2>();
	let mut verify_challenger = challenger.clone();

	let instance = FriInstanceInfo {
		oracles: vec![FriOracleInfo {
			num_polys: batch_size,
			blinding: false,
		}],
		batches: vec![FriBatchInfo {
			point: zeta,
			polynomials: (0..batch_size)
				.map(|i| FriPolynomialInfo {
					oracle_index: 0,
					polynomial_index: i,
				})
				.collect(),
		}],
	};

	let prove_timer = start_timer!(|| "prove");
	let proof = PolynomialBatch::prove_openings(
		&instance,
		&[&committed],
		&mut challenger,
		&fri_params,
		&mut timing_tree,
	);
	end_timer!(prove_timer);

	if print_proof_size {
		println!("Proof_size = {}", ByteSize(bincode::serialized_size(&proof).unwrap() as u64));
	}

	let challenges = verify_challenger.fri_challenges::<C, 2>(
		&proof.commit_phase_merkle_caps,
		&proof.final_poly,
		proof.pow_witness,
		fri_params.degree_bits,
		&fri_config,
	);

	let evals = committed
		.polynomials
		.iter()
		.map(|poly| poly.to_extension::<2>().eval(zeta))
		.collect::<Vec<_>>();
	let openings = FriOpenings {
		batches: vec![FriOpeningBatch { values: evals }],
	};

	let verify_timer = start_timer!(|| "verify");
	verify_fri_proof::<GoldilocksField, C, 2>(
		&instance,
		&openings,
		&challenges,
		&[committed.merkle_tree.cap.clone()],
		&proof,
		&fri_params,
	)
	.unwrap();
	end_timer!(verify_timer);

	println!();
}

fn main() {
	let batch_size = 256;
	for degree_bits in [12, 16, 20] {
		for n_bits in [64] {
			//[1, 8, 32, 64] {
			profile_commit_prove_verify::<PoseidonGoldilocksConfig>(
				degree_bits,
				n_bits,
				batch_size,
				true,
			);
			profile_commit_prove_verify::<KeccakGoldilocksConfig>(
				degree_bits,
				n_bits,
				batch_size,
				true,
			);
		}
	}
}
