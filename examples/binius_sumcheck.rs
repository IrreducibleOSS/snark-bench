use std::iter::repeat_with;

use ark_std::{end_timer, start_timer};
use binius_core::{
	fiat_shamir::HasherChallenger,
	polynomial::MultilinearComposite,
	protocols::{
		sumcheck::{
			batch_prove, batch_verify, immediate_switchover_heuristic,
			prove::RegularSumcheckProver, CompositeSumClaim, SumcheckClaim,
		},
		test_utils::TestProductComposition,
	},
	transcript::TranscriptWriter,
};
use binius_field::{
	BinaryField, BinaryField128b, BinaryField128bPolyval, BinaryField8b, ExtensionField, Field,
	PackedBinaryField1x128b, PackedBinaryField2x128b, PackedBinaryPolyval1x128b,
	PackedBinaryPolyval2x128b, PackedExtension, PackedField, PackedFieldIndexable,
	RepackedExtension, TowerField,
};
use binius_hal::make_portable_backend;
use binius_math::{
	CompositionPolyOS, IsomorphicEvaluationDomainFactory, MLEDirectAdapter, MultilinearExtension,
	MultilinearPoly,
};
use groestl::Groestl256;
use rand::{thread_rng, Rng};
use rayon::prelude::*;

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
	Composition: CompositionPolyOS<P>,
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

fn profile_sumcheck<F, FDomain, FChallenge, P>(id: &str, n_vars: usize, degree: usize)
where
	F: TowerField + ExtensionField<FDomain>,
	FDomain: BinaryField,
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
	let domain_factory = IsomorphicEvaluationDomainFactory::<FDomain>::default();
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

	let mut prover_transcript = TranscriptWriter::<HasherChallenger<Groestl256>>::default();

	let timer = start_timer!(|| "prove");
	let prover_reduced_claims = batch_prove(vec![prover], &mut prover_transcript).unwrap();
	end_timer!(timer);

	let mut verifier_transcript = prover_transcript.into_reader();

	let timer = start_timer!(|| "verify");
	let verifier_reduced_claims = batch_verify(&[claim], &mut verifier_transcript).unwrap();
	end_timer!(timer);

	// Check that challengers are in the same state
	assert_eq!(prover_reduced_claims, verifier_reduced_claims);
}

fn main() {
	for n_vars in [20, 24] {
		for degree in [2, 3, 4] {
			profile_sumcheck::<
				BinaryField128bPolyval,
				BinaryField128bPolyval,
				BinaryField128b,
				PackedBinaryPolyval1x128b,
			>("sumcheck 128b (POLYVAL basis)", n_vars, degree);
			profile_sumcheck::<
				BinaryField128b,
				BinaryField8b,
				BinaryField128b,
				PackedBinaryField1x128b,
			>("sumcheck 128b (tower basis)", n_vars, degree);
			profile_sumcheck::<
				BinaryField128bPolyval,
				BinaryField128bPolyval,
				BinaryField128b,
				PackedBinaryPolyval2x128b,
			>("sumcheck 128b (2x POLYVAL basis)", n_vars, degree);
			profile_sumcheck::<
				BinaryField128b,
				BinaryField8b,
				BinaryField128b,
				PackedBinaryField2x128b,
			>("sumcheck 128b (2x tower basis)", n_vars, degree);
			// profile_sumcheck::<
			// 	AESTowerField128b,
			// 	AESTowerField8b,
			// 	BinaryField128b,
			// 	ByteSlicedAES32x128b,
			// >("sumcheck 128b (Byte sliced)", n_vars, degree);
		}
	}
}
