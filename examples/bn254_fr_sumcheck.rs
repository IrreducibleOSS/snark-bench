// Copyright (c) Microsoft Corporation.
// Copyright 2023 Ulvetanna Inc.

use std::iter::repeat_with;

use ark_bn254::Fr;
use ark_std::{cfg_into_iter, end_timer, start_timer, One, UniformRand};
use jolt_core::{
	poly::dense_mlpoly::DensePolynomial, subprotocols::sumcheck::SumcheckInstanceProof,
	utils::transcript::ProofTranscript,
};
use rand::thread_rng;
use rayon::prelude::*;

fn profile_sumcheck<const ALPHA: usize>(num_vars: usize) {
	println!("n_vars={num_vars}, degree={ALPHA}");

	let num_evals = 1 << num_vars;

	let gen_timer = start_timer!(|| "generating polys");
	let polys = repeat_with(|| {
		let values = (0..num_evals)
			.into_par_iter()
			.map_init(thread_rng, |rng, _i| Fr::rand(rng))
			.collect::<Vec<_>>();
		DensePolynomial::new(values)
	})
	.take(ALPHA)
	.collect::<Vec<_>>();
	end_timer!(gen_timer);

	let claim_timer = start_timer!(|| "evaluating initial claim");
	let claim = cfg_into_iter!(0..num_evals)
		.map(|i| polys.iter().map(|poly| poly[i]).product::<Fr>())
		.sum();
	end_timer!(claim_timer);

	let comb_func_prod =
		|polys: &[Fr]| -> Fr { polys.iter().fold(Fr::one(), |acc, poly| acc * *poly) };

	let mut transcript = ProofTranscript::new(b"test");
	let mut prove_polys = polys.clone();

	let prove_timer = start_timer!(|| "prove sumcheck");
	let (proof, prove_randomness, _final_poly_evals) = SumcheckInstanceProof::<Fr>::prove_arbitrary(
		&claim,
		num_vars,
		&mut prove_polys,
		comb_func_prod,
		ALPHA,
		&mut transcript,
	);
	end_timer!(prove_timer);

	let mut transcript = ProofTranscript::new(b"test");

	let verify_timer = start_timer!(|| "verify sumcheck");
	let verify_result = proof.verify(claim, num_vars, ALPHA, &mut transcript);
	end_timer!(verify_timer);

	assert!(verify_result.is_ok());

	let (verify_evaluation, verify_randomness) = verify_result.unwrap();
	assert_eq!(prove_randomness, verify_randomness);

	let oracle_query = polys
		.iter()
		.map(|poly| poly.evaluate(prove_randomness.as_slice()))
		.product();
	assert_eq!(verify_evaluation, oracle_query);

	println!();
}

fn main() {
	for n_vars in [20, 24, 28] {
		profile_sumcheck::<2>(n_vars);
		profile_sumcheck::<3>(n_vars);
		profile_sumcheck::<4>(n_vars);
	}
}
