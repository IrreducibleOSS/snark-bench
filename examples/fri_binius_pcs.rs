// Copyright 2024 Irreducible Inc.

use std::iter::repeat_with;

use ark_std::{end_timer, start_timer};
use binius_core::{
	fiat_shamir::HasherChallenger,
	merkle_tree::{BinaryMerkleTreeProver, MerkleTreeProver},
	oracle::MultilinearOracleSet,
	piop,
	protocols::{evalcheck::EvalcheckMultilinearClaim, fri::CommitOutput},
	ring_switch,
	ring_switch::{EvalClaimSystem, ReducedClaim, ReducedWitness},
	tower::{AESTowerFamily, PackedTop, TowerFamily, TowerUnderlier},
	transcript::{AdviceWriter, CanRead, CanWrite, Proof, TranscriptWriter},
};
use binius_field::{
	arch::OptimalUnderlier,
	as_packed_field::{PackScalar, PackedType},
	underlier::UnderlierType,
	AESTowerField32b, AESTowerField8b, BinaryField1b, ExtensionField, Field, PackedExtension,
	PackedField, PackedFieldIndexable, TowerField,
};
use binius_hal::ComputationBackendExt;
use binius_hash::{Groestl256, GroestlDigest, HashDigest, HasherDigest};
use binius_math::{DefaultEvaluationDomainFactory, MultilinearExtension};
use binius_utils::rayon::adjust_thread_pool;
use p3_symmetric::{CompressionFunction, PseudoCompressionFunction};
use rand::thread_rng;

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

/// The cryptographic extension field that the constraint system protocol is defined over.
pub type FExt<Tower> = <Tower as TowerFamily>::B128;

/// The evaluation domain used in sumcheck protocols.
///
/// This is fixed to be 8-bits, which is large enough to handle all reasonable sumcheck
/// constraint degrees, even with a moderate number of skipped rounds using the univariate skip
/// technique.
pub type FDomain<Tower> = <Tower as TowerFamily>::B8;

/// The Reed–Solomon alphabet used for FRI encoding.
///
/// This is fixed to be 32-bits, which is large enough to handle trace sizes up to 64 GiB
/// of committed data.
pub type FEncode<Tower> = <Tower as TowerFamily>::B32;

fn test_commit_prove_verify_success<U, Tower, F>(n_vars: usize, log_inv_rate: usize)
where
	U: UnderlierType + TowerUnderlier<Tower> + PackScalar<F> + PackScalar<AESTowerField8b>,
	Tower: TowerFamily,
	F: TowerField,
	FExt<Tower>: PackedTop<Tower>
		+ ExtensionField<F>
		+ ExtensionField<AESTowerField8b>
		+ PackedExtension<F>
		+ PackedExtension<AESTowerField8b, PackedSubfield: PackedFieldIndexable>,
	PackedType<U, FExt<Tower>>: PackedFieldIndexable,
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

	let eval_point = repeat_with(|| <FExt<Tower> as Field>::random(&mut rng))
		.take(n_vars)
		.collect::<Vec<_>>();

	let eval_query = backend
		.multilinear_query::<PackedType<U, FExt<Tower>>>(&eval_point)
		.unwrap();
	let eval = multilin.evaluate(&eval_query).unwrap();

	let mut oracles = MultilinearOracleSet::new();
	let oracle_id = oracles.add_committed(n_vars, F::TOWER_LEVEL);

	let merkle_prover =
		BinaryMerkleTreeProver::<_, GroestlHasher<_>, _>::new(GroestlDigestCompression::default());
	let merkle_scheme = merkle_prover.scheme();

	let (commit_meta, oracle_to_commit_index) = piop::make_oracle_commit_meta(&oracles).unwrap();

	let fri_params = piop::make_commit_params_with_optimal_arity::<_, FEncode<Tower>, _>(
		&commit_meta,
		merkle_scheme,
		SECURITY_BITS,
		log_inv_rate,
	)
	.unwrap();

	let committed_multilins = [multilin.specialize_arc_dyn::<PackedType<U, FExt<Tower>>>()];

	let commit_timer = start_timer!(|| format!("commit, n_vars={}", n_vars));
	let commit_scope = tracing::debug_span!("commit").entered();
	let CommitOutput {
		commitment,
		committed,
		codeword,
	} = piop::commit(&fri_params, &merkle_prover, &committed_multilins).unwrap();
	drop(commit_scope);
	end_timer!(commit_timer);

	let mut proof = Proof {
		transcript: TranscriptWriter::<HasherChallenger<groestl::Groestl256>>::default(),
		advice: AdviceWriter::default(),
	};
	proof.transcript.write_packed(commitment.clone());

	let eval_claims = [EvalcheckMultilinearClaim {
		poly: oracles.oracle(oracle_id),
		eval_point: eval_point.into(),
		eval,
	}];
	let system = EvalClaimSystem::new(&commit_meta, oracle_to_commit_index, &eval_claims).unwrap();
	let domain_factory = DefaultEvaluationDomainFactory::<FDomain<Tower>>::default();

	let prove_timer = start_timer!(|| "prove");
	let prove_scope = tracing::debug_span!("prove").entered();
	let ReducedWitness {
		transparents: transparent_multilins,
		sumcheck_claims,
	} = ring_switch::prove::<_, _, _, Tower, _, _, _>(
		&system,
		&committed_multilins,
		&mut proof,
		&backend,
	)
	.unwrap();

	piop::prove(
		&fri_params,
		&merkle_prover,
		domain_factory,
		&commit_meta,
		committed,
		&codeword,
		&committed_multilins,
		&transparent_multilins,
		&sumcheck_claims,
		&mut proof,
		&backend,
	)
	.unwrap();
	drop(prove_scope);
	end_timer!(prove_timer);

	let mut proof = proof.into_verifier();
	let commitment = proof.transcript.read_packed().unwrap();

	let verify_timer = start_timer!(|| "verify");
	let verify_scope = tracing::debug_span!("verify").entered();

	let ReducedClaim {
		transparents,
		sumcheck_claims,
	} = ring_switch::verify::<_, Tower, _, _>(&system, &mut proof).unwrap();

	piop::verify(
		&commit_meta,
		merkle_scheme,
		&fri_params,
		&commitment,
		&transparents,
		&sumcheck_claims,
		&mut proof,
	)
	.unwrap();
	drop(verify_scope);
	end_timer!(verify_timer);

	println!();
}

fn main() {
	//binius_utils::tracing::init_tracing().expect("failed to initialize tracing");

	adjust_thread_pool()
		.as_ref()
		.expect("failed to init thread pool");

	let log_inv_rate = 2;
	for n_vars in [20, 24, 28] {
		println!("field=BinaryField1b n_vars={n_vars}");
		test_commit_prove_verify_success::<OptimalUnderlier, AESTowerFamily, BinaryField1b>(
			n_vars,
			log_inv_rate,
		);

		println!("field=AESTowerField8b n_vars={n_vars}");
		test_commit_prove_verify_success::<OptimalUnderlier, AESTowerFamily, AESTowerField8b>(
			n_vars,
			log_inv_rate,
		);

		println!("field=AESTowerField32b n_vars={n_vars}");
		test_commit_prove_verify_success::<OptimalUnderlier, AESTowerFamily, AESTowerField32b>(
			n_vars,
			log_inv_rate,
		);
	}
}
