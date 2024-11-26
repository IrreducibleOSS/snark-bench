// Copyright 2024 Ulvetanna Inc.

#![feature(step_trait)]

use ark_std::{end_timer, start_timer};
use binius_core::{
	challenger::CanObserve,
	fiat_shamir::HasherChallenger,
	merkle_tree_vcs::BinaryMerkleTreeProver,
	poly_commit::{PolyCommitScheme, FRIPCS},
	transcript::{AdviceWriter, Proof, TranscriptWriter},
};
use binius_field::{
	arch::OptimalUnderlier,
	as_packed_field::{PackScalar, PackedType},
	underlier::{Divisible, UnderlierType},
	AESTowerField128b, AESTowerField32b, AESTowerField8b, BinaryField, BinaryField1b,
	ExtensionField, Field, PackedExtension, PackedField, PackedFieldIndexable, TowerField,
};
use binius_hal::ComputationBackendExt;
use binius_hash::{Groestl256, GroestlDigest, HashDigest, HasherDigest};
use binius_math::{IsomorphicEvaluationDomainFactory, MultilinearExtension};
use binius_ntt::{NTTOptions, ThreadingSettings};
use binius_utils::rayon::adjust_thread_pool;
use p3_symmetric::{CompressionFunction, PseudoCompressionFunction};
use rand::thread_rng;
use std::iter::{repeat_with, Step};

const SECURITY_BITS: usize = 96;

pub type GroestlDigestAES = GroestlDigest<AESTowerField8b>;
pub type GroestlHasher<P> = Groestl256<P, AESTowerField8b>;

#[derive(Debug, Default, Clone)]
pub struct GroestlDigestCompression;

impl PseudoCompressionFunction<GroestlDigestAES, 2> for GroestlDigestCompression {
	fn compress(&self, input: [GroestlDigestAES; 2]) -> GroestlDigestAES {
		HasherDigest::<GroestlDigestAES, GroestlHasher<GroestlDigestAES>>::hash(&input[..])
	}
}

impl CompressionFunction<GroestlDigestAES, 2> for GroestlDigestCompression {}

fn test_commit_prove_verify_success<U, F, FDomain, FEncode, FE>(n_vars: usize, log_inv_rate: usize)
where
	U: UnderlierType
		+ PackScalar<F>
		+ PackScalar<FDomain>
		+ PackScalar<FEncode>
		+ PackScalar<FE>
		+ PackScalar<AESTowerField8b>
		+ Divisible<u8>,
	F: TowerField,
	FDomain: TowerField,
	FDomain::Canonical: Step,
	FEncode: BinaryField,
	FE: TowerField
		+ ExtensionField<F>
		+ ExtensionField<FEncode>
		+ ExtensionField<FDomain>
		+ ExtensionField<AESTowerField8b>
		+ PackedField<Scalar = FE>
		+ PackedExtension<F>
		+ PackedExtension<FEncode>
		+ PackedExtension<FDomain>
		+ PackedExtension<AESTowerField8b, PackedSubfield: PackedFieldIndexable>,
	PackedType<U, FEncode>: PackedFieldIndexable,
	PackedType<U, FE>: PackedFieldIndexable,
{
	let backend = binius_hal::make_portable_backend();
	let mut rng = thread_rng();

	let gen_timer = start_timer!(|| "generate");
	let multilin = tracing::debug_span!("generate").in_scope(|| {
		MultilinearExtension::from_values(
			repeat_with(|| <PackedType<U, F>>::random(&mut rng))
				.take(1 << (n_vars - <PackedType<U, F>>::LOG_WIDTH))
				.collect(),
		)
		.unwrap()
	});
	assert_eq!(multilin.n_vars(), n_vars);
	end_timer!(gen_timer);

	let eval_point = repeat_with(|| <FE as Field>::random(&mut rng))
		.take(n_vars)
		.collect::<Vec<_>>();

	let eval_query = backend
		.multilinear_query::<PackedType<U, FE>>(&eval_point)
		.unwrap();
	let eval = multilin.evaluate(&eval_query).unwrap();

	let merkle_prover =
		BinaryMerkleTreeProver::<_, GroestlHasher<_>, _>::new(GroestlDigestCompression::default());

	let pcs = FRIPCS::<F, FDomain, FEncode, PackedType<U, FE>, _, _, _>::with_optimal_arity(
		n_vars,
		log_inv_rate,
		SECURITY_BITS,
		merkle_prover,
		IsomorphicEvaluationDomainFactory::<FDomain::Canonical>::default(),
		NTTOptions {
			precompute_twiddles: true,
			thread_settings: ThreadingSettings::MultithreadedDefault,
		},
	)
	.unwrap();

	let commit_timer = start_timer!(|| format!("commit, n_vars={}", n_vars));
	let (commitment, committed) =
		tracing::debug_span!("commit").in_scope(|| pcs.commit(&[multilin.to_ref()]).unwrap());
	end_timer!(commit_timer);

	let mut proof = Proof {
		transcript: TranscriptWriter::<HasherChallenger<groestl::Groestl256>>::default(),
		advice: AdviceWriter::default(),
	};
	proof.transcript.observe(commitment.clone());

	let prove_timer = start_timer!(|| "prove");
	tracing::debug_span!("prove").in_scope(|| {
		pcs.prove_evaluation(
			&mut proof.advice,
			&mut proof.transcript,
			&committed,
			&[multilin],
			&eval_point,
			&backend,
		)
		.unwrap()
	});
	end_timer!(prove_timer);

	let mut proof = proof.into_verifier();
	proof.transcript.observe(commitment.clone());

	let verify_timer = start_timer!(|| "verify");
	tracing::debug_span!("verify").in_scope(|| {
		pcs.verify_evaluation(
			&mut proof.advice,
			&mut proof.transcript,
			&commitment,
			&eval_point,
			&[eval],
			&backend,
		)
		.unwrap();
	});
	end_timer!(verify_timer);

	println!();
}

fn main() {
	//binius_utils::tracing::init_tracing().expect("failed to initialize tracing");

	adjust_thread_pool()
		.as_ref()
		.expect("failed to init thread pool");

	let log_inv_rate = 1;
	for n_vars in [20, 24] {
		println!("field=BinaryField1b n_vars={n_vars}");
		test_commit_prove_verify_success::<
			OptimalUnderlier,
			BinaryField1b,
			AESTowerField8b,
			AESTowerField32b,
			AESTowerField128b,
		>(n_vars, log_inv_rate);

		println!("field=AESTowerField8b n_vars={n_vars}");
		test_commit_prove_verify_success::<
			OptimalUnderlier,
			AESTowerField8b,
			AESTowerField8b,
			AESTowerField32b,
			AESTowerField128b,
		>(n_vars, log_inv_rate);

		println!("field=AESTowerField32b n_vars={n_vars}");
		test_commit_prove_verify_success::<
			OptimalUnderlier,
			AESTowerField32b,
			AESTowerField8b,
			AESTowerField32b,
			AESTowerField128b,
		>(n_vars, log_inv_rate);
	}
}
