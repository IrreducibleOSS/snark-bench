use binius_field::{AESTowerField8b, BinaryField8b};
use criterion::{
	black_box, criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup,
	Criterion, Throughput,
};
use rand::{
	distributions::{Distribution, Standard},
	thread_rng, Rng,
};

pub fn bench_ark_bn254(c: &mut Criterion) {
	use ark_bn254::Fr;
	use ark_std::UniformRand;

	let mut rng = thread_rng();
	let mut group = c.benchmark_group("ark_bn254 multiply");

	let x = Fr::rand(&mut rng);
	let y = Fr::rand(&mut rng);
	group.throughput(Throughput::Elements(1));
	group.bench_function("B254 Fr", |b| b.iter(|| black_box(x) * black_box(y)));

	group.finish()
}

fn bench_risc0(c: &mut Criterion) {
	use risc0_core::field::{baby_bear::BabyBear, Elem, Field};

	fn benchmark_mul<F: Elem, M: Measurement>(
		group: &mut BenchmarkGroup<M>,
		mut rng: impl Rng,
		name: &str,
	) {
		let x = F::random(&mut rng);
		let y = F::random(&mut rng);
		group.throughput(Throughput::Elements(1));
		group.bench_function(name, |b| b.iter(|| black_box(x) * black_box(y)));
	}

	let mut rng = thread_rng();
	let mut group = c.benchmark_group("risc0 multiply");

	benchmark_mul::<<BabyBear as Field>::Elem, _>(&mut group, &mut rng, "BB31");
	benchmark_mul::<<BabyBear as Field>::ExtElem, _>(&mut group, &mut rng, "BB31^4");

	group.finish()
}

fn bench_binius(c: &mut Criterion) {
	use binius_field::{
		arch::OptimalUnderlier, as_packed_field::PackedType, AESTowerField128b, AESTowerField32b,
		BinaryField128b, BinaryField128bPolyval, BinaryField32b, PackedField,
	};

	fn benchmark_mul<P: PackedField, M: Measurement>(
		group: &mut BenchmarkGroup<M>,
		mut rng: impl Rng,
		name: &str,
	) {
		let x = P::random(&mut rng);
		let y = P::random(&mut rng);
		group.throughput(Throughput::Elements(P::WIDTH as u64));
		group.bench_function(name, |b| b.iter(|| black_box(x) * black_box(y)));
	}

	let mut rng = thread_rng();
	let mut group = c.benchmark_group("binius multiply");

	type U = OptimalUnderlier;
	benchmark_mul::<PackedType<U, BinaryField8b>, _>(&mut group, &mut rng, "Tower 8b");
	benchmark_mul::<PackedType<U, AESTowerField8b>, _>(
		&mut group,
		&mut rng,
		"Mixed AES Tower 8b",
	);
	benchmark_mul::<PackedType<U, BinaryField32b>, _>(&mut group, &mut rng, "Tower 32b");
	benchmark_mul::<PackedType<U, AESTowerField32b>, _>(
		&mut group,
		&mut rng,
		"Mixed AES Tower 32b",
	);
	benchmark_mul::<PackedType<U, BinaryField128b>, _>(&mut group, &mut rng, "Tower 128b");
	benchmark_mul::<PackedType<U, AESTowerField128b>, _>(
		&mut group,
		&mut rng,
		"Mixed AES Tower 128b",
	);
	benchmark_mul::<PackedType<U, BinaryField128bPolyval>, _>(&mut group, &mut rng, "POLYVAL");

	group.finish()
}

fn bench_plonky2(c: &mut Criterion) {
	use plonky2_field::{
		extension::quadratic::QuadraticExtension, goldilocks_field::GoldilocksField,
		packable::Packable, packed::PackedField, types::Field,
	};

	fn benchmark_scalar_mul<F: Field, M: Measurement>(
		group: &mut BenchmarkGroup<M>,
		mut rng: impl Rng,
		name: &str,
	) {
		let x = F::sample(&mut rng);
		let y = F::sample(&mut rng);
		group.throughput(Throughput::Elements(1));
		group.bench_function(name, |b| b.iter(|| black_box(x) * black_box(y)));
	}

	fn benchmark_packed_mul<F: Packable, M: Measurement>(
		group: &mut BenchmarkGroup<M>,
		mut rng: impl Rng,
		name: &str,
	) {
		let mut x = F::Packing::default();
		let mut y = F::Packing::default();

		for x_i in x.as_slice_mut().iter_mut() {
			*x_i = F::sample(&mut rng);
		}
		for y_i in y.as_slice_mut().iter_mut() {
			*y_i = F::sample(&mut rng);
		}

		group.throughput(Throughput::Elements(F::Packing::WIDTH as u64));
		group.bench_function(name, |b| b.iter(|| black_box(x) * black_box(y)));
	}

	let mut rng = thread_rng();
	let mut group = c.benchmark_group("plonky2 multiply");

	benchmark_packed_mul::<GoldilocksField, _>(&mut group, &mut rng, "GL64");
	benchmark_scalar_mul::<QuadraticExtension<GoldilocksField>, _>(&mut group, &mut rng, "GL64^2");

	group.finish()
}

fn bench_plonky3(c: &mut Criterion) {
	use p3_baby_bear::BabyBear;
	use p3_field::{
		extension::{BinomialExtensionField, Complex},
		Field, PackedValue,
	};
	use p3_goldilocks::Goldilocks;
	use p3_mersenne_31::Mersenne31;

	fn benchmark_mul<F: Field, M: Measurement>(
		group: &mut BenchmarkGroup<M>,
		mut rng: impl Rng,
		name: &str,
	) where
		Standard: Distribution<F>,
	{
		let x = F::Packing::from_fn(|_| rng.gen());
		let y = F::Packing::from_fn(|_| rng.gen());
		group.throughput(Throughput::Elements(F::Packing::WIDTH as u64));
		group.bench_function(name, |b| b.iter(|| black_box(x) * black_box(y)));
	}

	let mut rng = thread_rng();
	let mut group = c.benchmark_group("plonky3 multiply");

	benchmark_mul::<Goldilocks, _>(&mut group, &mut rng, "GL64");
	benchmark_mul::<BinomialExtensionField<Goldilocks, 2>, _>(&mut group, &mut rng, "GL64^2");
	benchmark_mul::<BabyBear, _>(&mut group, &mut rng, "BB31");
	benchmark_mul::<BinomialExtensionField<BabyBear, 4>, _>(&mut group, &mut rng, "BB31^4");
	benchmark_mul::<Mersenne31, _>(&mut group, &mut rng, "M31");
	benchmark_mul::<BinomialExtensionField<Complex<Mersenne31>, 2>, _>(
		&mut group, &mut rng, "M31^4",
	);

	group.finish()
}

criterion_group!(
	field_ops,
	bench_ark_bn254,
	bench_risc0,
	bench_binius,
	bench_plonky2,
	bench_plonky3
);
criterion_main!(field_ops);
