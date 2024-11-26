#![feature(step_trait)]

use ark_std::{end_timer, start_timer};
use binius_core::{
	challenger::{new_hasher_challenger, CanSample, IsomorphicChallenger},
	polynomial::MultilinearComposite,
	protocols::{
		sumcheck::{
			batch_prove, batch_verify, immediate_switchover_heuristic,
			prove::RegularSumcheckProver, CompositeSumClaim, SumcheckClaim,
		},
		test_utils::TestProductComposition,
	},
};
use binius_field::{
	arch::byte_sliced::ByteSlicedAES32x128b, AESTowerField128b, AESTowerField8b, BinaryField128b,
	BinaryField128bPolyval, BinaryField8b, ExtensionField, Field, PackedBinaryField1x128b,
	PackedBinaryField2x128b, PackedBinaryPolyval1x128b, PackedBinaryPolyval2x128b, PackedExtension,
	PackedField, PackedFieldIndexable, RepackedExtension,
};
use binius_hal::make_portable_backend;
use binius_hash::GroestlHasher;
use binius_math::{
	CompositionPoly, IsomorphicEvaluationDomainFactory, MLEDirectAdapter, MLEEmbeddingAdapter,
	MultilinearExtension, MultilinearPoly,
};
use rand::{thread_rng, Rng};
use rayon::prelude::*;
use std::iter::{repeat_with, Step};

fn generate_random_multilinears<P>(
	mut rng: impl Rng,
	n_vars: usize,
	n_multilinears: usize,
) -> Vec<MLEDirectAdapter<P>>
where
	P: PackedField + RepackedExtension<P>,
{
	repeat_with(|| {
		let values = repeat_with(|| P::random(&mut rng))
			.take(1 << (n_vars - P::LOG_WIDTH))
			.collect::<Vec<_>>();
		MultilinearExtension::from_values(values).unwrap().into()
	})
	.take(n_multilinears)
	.collect()
}

fn compute_composite_sum<F, P, M, Composition>(multilinears: &[M], composition: Composition) -> F
where
	F: Field,
	P: PackedField<Scalar = F>,
	M: MultilinearPoly<P> + Send + Sync,
	Composition: CompositionPoly<P>,
{
	let n_vars = multilinears
		.first()
		.map(|multilinear| multilinear.n_vars())
		.unwrap_or_default();
	for multilinear in multilinears.iter() {
		assert_eq!(multilinear.n_vars(), n_vars);
	}

	let multilinears = multilinears.iter().collect::<Vec<_>>();
	let witness = MultilinearComposite::new(n_vars, composition, multilinears.clone()).unwrap();
	(0..(1 << n_vars))
		.into_par_iter()
		.map(|j| witness.evaluate_on_hypercube(j).unwrap())
		.sum()
}

fn profile_sumcheck<F, FDomain, FStep, FChallenge, P>(id: &str, n_vars: usize, degree: usize)
where
	F: Field + ExtensionField<FDomain>,
	FDomain: Field + From<FStep>,
	FStep: Field + Step,
	FChallenge: Field
		+ PackedField<Scalar = FChallenge>
		+ From<F>
		+ Into<F>
		+ ExtensionField<BinaryField8b>
		+ PackedExtension<BinaryField8b, PackedSubfield: PackedFieldIndexable>,
	P: PackedField<Scalar = F> + PackedExtension<FDomain> + RepackedExtension<P>,
{
	println!("{id}, n_vars={n_vars}, degree={degree}");

	let mut rng = thread_rng();

	let n_multilinears = degree;
	let composition = TestProductComposition::new(n_multilinears);

	let timer = start_timer!(|| "generating polys");
	let multilins = generate_random_multilinears::<P>(&mut rng, n_vars, n_multilinears);
	end_timer!(timer);

	let timer = start_timer!(|| "evaluating initial claim");

	let sum = compute_composite_sum(&multilins, &composition);
	end_timer!(timer);

	let claim = SumcheckClaim::new(
		n_vars,
		n_multilinears,
		vec![CompositeSumClaim {
			composition: &composition,
			sum,
		}],
	)
	.unwrap();

	let backend = make_portable_backend();
	let domain_factory = IsomorphicEvaluationDomainFactory::<FStep>::default();
	let prover = RegularSumcheckProver::<FDomain, _, _, _, _>::new(
		multilins.iter().collect(),
		[CompositeSumClaim {
			composition: &composition,
			sum,
		}],
		domain_factory,
		immediate_switchover_heuristic,
		&backend,
	)
	.unwrap();

	let challenger = IsomorphicChallenger::<FChallenge, _, F>::new(new_hasher_challenger::<
		_,
		GroestlHasher<_>,
	>());

	let mut prover_challenger = challenger.clone();

	let timer = start_timer!(|| "prove");
	let (_, proof) =
		batch_prove(vec![prover], &mut prover_challenger).expect("failed to prove sumcheck");
	end_timer!(timer);

	let mut verifier_challenger = challenger.clone();

	let timer = start_timer!(|| "verify");
	let _ = batch_verify(&[claim], proof, &mut verifier_challenger).unwrap();
	end_timer!(timer);

	// Check that challengers are in the same state
	assert_eq!(
		CanSample::<F>::sample(&mut prover_challenger),
		CanSample::<F>::sample(&mut verifier_challenger)
	);
}

fn main() {
	for n_vars in [20, 24] {
		for degree in [2, 3, 4] {
			profile_sumcheck::<
				BinaryField128bPolyval,
				BinaryField128bPolyval,
				BinaryField128b,
				BinaryField128b,
				PackedBinaryPolyval1x128b,
			>("sumcheck 128b (POLYVAL basis)", n_vars, degree);
			profile_sumcheck::<
				BinaryField128b,
				BinaryField8b,
				BinaryField8b,
				BinaryField128b,
				PackedBinaryField1x128b,
			>("sumcheck 128b (tower basis)", n_vars, degree);
			profile_sumcheck::<
				BinaryField128bPolyval,
				BinaryField128bPolyval,
				BinaryField128b,
				BinaryField128b,
				PackedBinaryPolyval2x128b,
			>("sumcheck 128b (2x POLYVAL basis)", n_vars, degree);
			profile_sumcheck::<
				BinaryField128b,
				BinaryField8b,
				BinaryField8b,
				BinaryField128b,
				PackedBinaryField2x128b,
			>("sumcheck 128b (2x tower basis)", n_vars, degree);
			// profile_sumcheck::<
			// 	AESTowerField128b,
			// 	AESTowerField8b,
			// 	BinaryField8b,
			// 	BinaryField128b,
			// 	ByteSlicedAES32x128b,
			// >("sumcheck 128b (Byte sliced)", n_vars, degree);
		}
	}
}
