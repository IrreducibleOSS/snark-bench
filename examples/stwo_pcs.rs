// Copyright 2024 Irreducible Inc.

use ark_std::{end_timer, start_timer, UniformRand};
use rand::thread_rng;
use stwo::core::{
	backend::{simd::SimdBackend, Col, Column},
	channel::Blake2sChannel,
	circle::CirclePoint,
	fields::{m31::BaseField, qm31::SecureField},
	fri::FriConfig,
	pcs::{CommitmentSchemeProver, CommitmentSchemeVerifier, PcsConfig, TreeVec},
	poly::{
		circle::{CanonicCoset, CircleEvaluation, PolyOps},
		BitReversedOrder,
	},
	vcs::blake2_merkle::Blake2sMerkleChannel,
	ColumnVec,
};

const SECURITY_BITS: usize = 96;

fn run_commit_prove_verify_stwo_pcs(log_n_rows: u32, log_batch_size: u32, log_blowup_factor: u32) {
	println!("stwo pcs with log_coeffs={}", log_n_rows + log_batch_size);

	// Precompute twiddles.
	let precompute_timer = start_timer!(|| "precompute twiddles");
	let twiddles = SimdBackend::precompute_twiddles(
		CanonicCoset::new(log_n_rows + log_blowup_factor)
			.circle_domain()
			.half_coset,
	);
	end_timer!(precompute_timer);

	// Setup protocol.
	let channel = &mut Blake2sChannel::default();
	let pcs_config = PcsConfig {
		pow_bits: 0,
		fri_config: FriConfig {
			log_last_layer_degree_bound: 0,
			log_blowup_factor,
			n_queries: calculate_n_test_queries(SECURITY_BITS, log_blowup_factor as usize),
		},
	};
	let prove_commitment_scheme =
		&mut CommitmentSchemeProver::<_, Blake2sMerkleChannel>::new(pcs_config, &twiddles);

	// Generate trace.
	let gen_trace_timer = start_timer!(|| "generate trace");
	let domain = CanonicCoset::new(log_n_rows).circle_domain();
	let mut trace = (0..1 << log_batch_size)
		.map(|_| Col::<SimdBackend, BaseField>::zeros(1 << log_n_rows))
		.collect::<Vec<_>>();
	let mut rng = thread_rng();
	for col in trace.iter_mut() {
		for val in col.as_mut_slice() {
			*val = BaseField::rand(&mut rng);
		}
	}
	end_timer!(gen_trace_timer);

	// Commit trace
	let commit_timer = start_timer!(|| "commit trace");
	let trace = trace
		.into_iter()
		.map(|eval| CircleEvaluation::<SimdBackend, BaseField, BitReversedOrder>::new(domain, eval))
		.collect::<Vec<_>>();

	let mut tree_builder = prove_commitment_scheme.tree_builder();
	tree_builder.extend_evals(trace);
	tree_builder.commit(channel);
	end_timer!(commit_timer);

	// Prove
	let proove_timer = start_timer!(|| "prove");
	let sample_point = CirclePoint::<SecureField>::get_random_point(channel);
	let sample_points = vec![ColumnVec::<Vec<CirclePoint<SecureField>>>::from(
		(0..1 << log_batch_size)
			.map(|_| vec![sample_point])
			.collect::<Vec<_>>(),
	)];
	let sample_points = TreeVec::new(sample_points);
	let proof = prove_commitment_scheme.prove_values(sample_points.clone(), channel);
	end_timer!(proove_timer);

	// Verify
	let verify_timer = start_timer!(|| "verify");
	let channel = &mut Blake2sChannel::default();
	let commitment_scheme: &mut CommitmentSchemeVerifier<Blake2sMerkleChannel> =
		&mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(pcs_config);
	commitment_scheme.commit(
		prove_commitment_scheme.roots()[0],
		&vec![log_n_rows; 1 << log_batch_size],
		channel,
	);
	commitment_scheme
		.verify_values(sample_points, proof, channel)
		.unwrap();
	end_timer!(verify_timer);
}

fn calculate_n_test_queries(security_bits: usize, log_blowup_factor: usize) -> usize {
	let per_query_err = 0.5 * (1f64 + 2.0f64.powi(-(log_blowup_factor as i32)));
	(-(security_bits as f64) / per_query_err.log2()).ceil() as usize
}

fn main() {
	//binius_utils::tracing::init_tracing().expect("failed to initialize tracing");

	let log_batch_size = 4;
	let log_inv_rate = 1;
	for log_degree in [20, 24] {
		run_commit_prove_verify_stwo_pcs(log_degree, log_batch_size, log_inv_rate);
	}
}
