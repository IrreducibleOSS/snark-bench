use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::{thread_rng, Rng};
use std::array;

fn bench_sha2(c: &mut Criterion) {
	use sha2::{Digest, Sha256};

	let mut group = c.benchmark_group("SHA2");
	let mut rng = thread_rng();

	group.throughput(Throughput::Bytes(1024 * 1024));
	let data: [u8; 1024 * 1024] = array::from_fn(|_| rng.gen());
	group.bench_function("digest", |b| {
		b.iter(|| <Sha256 as Digest>::digest(&data));
	});
	group.finish()
}

fn bench_keccak(c: &mut Criterion) {
	use tiny_keccak::{Hasher, Keccak};

	let mut group = c.benchmark_group("Keccak-256");
	let mut rng = thread_rng();

	group.throughput(Throughput::Bytes(1024 * 1024));
	let data: [u8; 1024 * 1024] = array::from_fn(|_| rng.gen());
	group.bench_function("digest", |b| {
		b.iter(|| {
			let mut digest = [0u8; 32];
			let mut keccak = Keccak::v256();
			keccak.update(&data);
			keccak.finalize(&mut digest);
			digest
		});
	});
	group.finish()
}

fn bench_groestl(c: &mut Criterion) {
	use binius_field::{AESTowerField8b, PackedField};
	use binius_hash::{Groestl256, HashDigest, HasherDigest};

	let mut group = c.benchmark_group("Groestl");
	let mut rng = thread_rng();

	group.throughput(Throughput::Bytes(1024 * 1024));
	let data: [AESTowerField8b; 1024 * 1024] =
		array::from_fn(|_| AESTowerField8b::random(&mut rng));

	group.bench_function("digest", |b| {
		b.iter(|| HasherDigest::<_, Groestl256<_, AESTowerField8b>>::hash(data.as_slice()));
	});
	group.finish()
}

fn bench_blake2(c: &mut Criterion) {
	use blake2::{digest::consts::U32, Blake2b, Digest};

	let mut group = c.benchmark_group("Blake2");
	let mut rng = thread_rng();

	group.throughput(Throughput::Bytes(1024 * 1024));
	let data: [u8; 1024 * 1024] = array::from_fn(|_| rng.gen());
	group.bench_function("digest", |b| {
		b.iter(|| <Blake2b<U32>>::digest(&data));
	});
	group.finish()
}

fn bench_blake3(c: &mut Criterion) {
	let mut group = c.benchmark_group("Blake3");
	let mut rng = thread_rng();

	group.throughput(Throughput::Bytes(1024 * 1024));
	let data: [u8; 1024 * 1024] = array::from_fn(|_| rng.gen());
	group.bench_function("digest", |b| {
		b.iter(|| blake3::hash(&data));
	});
	group.finish()
}

fn bench_poseidon_gl64(c: &mut Criterion) {
	use plonky2::{hash::poseidon::PoseidonHash, plonk::config::Hasher};
	use plonky2_field::{goldilocks_field::GoldilocksField, types::Sample};

	let mut group = c.benchmark_group("Poseidon-GL64");

	group.throughput(Throughput::Bytes(1024 * 1024));
	let data = GoldilocksField::rand_vec(1024 * 1024 / 8);

	group.bench_function("digest", |b| b.iter(|| PoseidonHash::hash_no_pad(&data)));
	group.finish()
}

fn bench_poseidon2_bb31(c: &mut Criterion) {
	use risc0_core::field::{baby_bear::BabyBearElem, Elem};
	use risc0_zkp::core::hash::poseidon2::Poseidon2HashSuite;

	let mut group = c.benchmark_group("Poseidon2-BB31");
	let mut rng = thread_rng();

	group.throughput(Throughput::Bytes(1024 * 1024));
	let data: [BabyBearElem; 1024 * 1024 / 4] = array::from_fn(|_| BabyBearElem::random(&mut rng));

	let hash_suite = Poseidon2HashSuite::new_suite();

	group.bench_function("digest", |b| b.iter(|| hash_suite.hashfn.hash_elem_slice(&data)));
	group.finish()
}

fn bench_vision32(c: &mut Criterion) {
	use binius_field::{
		BinaryField32b, BinaryField8b, ExtensionField, PackedBinaryField4x32b, PackedField,
	};
	use binius_hash::{FixedLenHasherDigest, HashDigest, Vision32b};

	let mut group = c.benchmark_group("Vision");

	let mut rng = thread_rng();

	const N: usize = 1 << 12;
	let data: [PackedBinaryField4x32b; N] =
		array::from_fn(|_| PackedBinaryField4x32b::random(&mut rng));

	group.throughput(Throughput::Bytes(
		(N * PackedBinaryField4x32b::WIDTH
			* <BinaryField32b as ExtensionField<BinaryField8b>>::DEGREE) as u64,
	));
	group.bench_function("Vision32b", |bench| {
		bench.iter(|| FixedLenHasherDigest::<_, Vision32b<_>>::hash(data))
	});

	group.finish()
}

fn p3_bench_poseidon2_m31(c: &mut Criterion) {
	use p3_field::{Field, PackedValue};
	use p3_mersenne_31::{DiffusionMatrixMersenne31, Mersenne31};
	use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
	use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

	let mut group = c.benchmark_group("Plonky3-Poseidon2-MR31");

	let mut rng = thread_rng();

	type Perm =
		Poseidon2<Mersenne31, Poseidon2ExternalMatrixGeneral, DiffusionMatrixMersenne31, 16, 5>;
	let perm = Perm::new_from_rng_128(
		Poseidon2ExternalMatrixGeneral,
		DiffusionMatrixMersenne31,
		&mut thread_rng(),
	);

	const WIDTH: usize = 16;

	type PackedField = <Mersenne31 as Field>::Packing;

	type MyHash = PaddingFreeSponge<Perm, WIDTH, 8, 8>;
	let hash = MyHash::new(perm.clone());

	group.throughput(Throughput::Bytes(1024 * 1024));

	let data: [PackedField; 1024 * 1024 / 4 / PackedField::WIDTH] = array::from_fn(|_| rng.gen());

	group.bench_function("digest", |b| {
		b.iter(|| {
			hash.hash_iter(data);
		})
	});
	group.finish()
}

fn p3_bench_poseidon2_bb31(c: &mut Criterion) {
	use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
	use p3_field::{Field, PackedValue};
	use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
	use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

	let mut group = c.benchmark_group("Plonky3-Poseidon2-BB31");

	let mut rng = thread_rng();

	type Perm = Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
	let perm = Perm::new_from_rng_128(
		Poseidon2ExternalMatrixGeneral,
		DiffusionMatrixBabyBear::default(),
		&mut thread_rng(),
	);

	const WIDTH: usize = 16;

	type PackedField = <BabyBear as Field>::Packing;

	type MyHash = PaddingFreeSponge<Perm, WIDTH, 8, 8>;
	let hash = MyHash::new(perm.clone());

	group.throughput(Throughput::Bytes(1024 * 1024));

	let data: [PackedField; 1024 * 1024 / 4 / PackedField::WIDTH] = array::from_fn(|_| rng.gen());

	group.bench_function("digest", |b| {
		b.iter(|| {
			hash.hash_iter(data);
		})
	});
	group.finish()
}

criterion_group!(
	bench_hashing,
	bench_sha2,
	bench_groestl,
	bench_blake2,
	bench_blake3,
	bench_keccak,
	bench_poseidon_gl64,
	bench_poseidon2_bb31,
	bench_vision32,
	p3_bench_poseidon2_m31,
	p3_bench_poseidon2_bb31
);
criterion_main!(bench_hashing);
