// Copyright (c) Microsoft Corporation.
// Copyright 2023-2024 Ulvetanna Inc.

use ark_bn254::{Fr, G1Projective};
use ark_std::{end_timer, start_timer, UniformRand};
use jolt_core::{
	poly::{
		commitment::{
			commitment_scheme::{BatchType, CommitShape, CommitmentScheme},
			hyrax::HyraxScheme,
		},
		dense_mlpoly::DensePolynomial,
	},
	utils::transcript::ProofTranscript,
};
use rand::{thread_rng, Rng};
use std::iter::repeat_with;

fn profile_lasso(n_vars: usize, n_bits: usize) {
	let mut rng = thread_rng();

	let num_evals = 1 << n_vars;

	type PCS = HyraxScheme<G1Projective>;
	let pcs_setup = PCS::setup(&[CommitShape::new(num_evals, BatchType::Small)]);
	let mat_width = pcs_setup.generators.len();
	let mat_width_log2 = mat_width.ilog2();

	println!("n_vars={n_vars}, n_bits={n_bits}, mat_width_log2={mat_width_log2}");

	let gen_timer = start_timer!(|| format!("gen_data, n_vars={n_vars}, n_bits={n_bits}"));
	let poly = DensePolynomial::new(
		repeat_with(|| Fr::from(rng.gen_range(0..(1u128 << n_bits))))
			.take(num_evals)
			.collect(),
	);
	end_timer!(gen_timer);

	let commit_timer = start_timer!(|| format!("commit"));
	let commitment = PCS::commit(&poly, &pcs_setup);
	end_timer!(commit_timer);

	let r = repeat_with(|| Fr::rand(&mut rng))
		.take(n_vars)
		.collect::<Vec<_>>();
	let eval = poly.evaluate(&r);

	let prove_timer = start_timer!(|| format!("prove"));
	let mut prover_transcript = ProofTranscript::new(b"example");
	let proof = PCS::prove(&pcs_setup, &poly, &r, &mut prover_transcript);
	end_timer!(prove_timer);

	let verify_timer = start_timer!(|| format!("verify"));
	let mut verifier_transcript = ProofTranscript::new(b"example");
	let verify_result =
		PCS::verify(&proof, &pcs_setup, &mut verifier_transcript, &r, &eval, &commitment);
	assert!(verify_result.is_ok());
	end_timer!(verify_timer);

	println!();
}

fn main() {
	for n_vars in [16, 20, 24, 28] {
		for n_bits in [1, 8, 32, 64] {
			profile_lasso(n_vars, n_bits);
		}
	}
}
