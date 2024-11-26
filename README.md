# Irreducible's SNARK Benchmarks

This is a repository for benchmark comparisons between SNARK implementations.

We have benchmarks for low-level operations like field multiplication throughput and hashing throughput. For higher level cryptographic protocols like polynomial commitment schemes and sumcheck, the code is run with Cargo "example" targets.

We update the benchmarks periodically, but we do _not_ guarantee that they are up-to-date at all times. We welcome merge requests to update the benchmarks.

## Environment

Many of the benchmarked libraries use architecture-specific optimizations. Ensure your toolchain is configured to use them by setting the environment variable:

```bash
export RUSTFLAGS="-Ctarget-cpu=native"
```

Most packages use [rayon](https://docs.rs/rayon/latest/rayon/) for multithreading. The level of parallelism can be controlled with the `RAYON_NUM_THREADS` environment variable.

## Microbenchmarks

The `benches/` directory contains low-level microbenchmarks implemented with Criterion.

## Cryptographic Protocols

More expensive cryptographic protocols are too slow to run with Criterion, which requires enough samples to get statistical bounds on accuracy. We implement the cryptographic protocols with Cargo "example" targets. Make sure to run them with the "release" profile. For example, you can run

```bash
$ cargo run --release --example fri_binius_pcs
    Finished `release` profile [optimized] target(s) in 0.89s
     Running `target/release/examples/fri_binius_pcs`
field=BinaryField1b n_vars=20
Start:   generate
End:     generate ..................................................................157.275µs
Start:   commit, n_vars=20
End:     commit, n_vars=20 .........................................................2.886ms
Start:   prove
End:     prove .....................................................................10.648ms
Start:   verify
End:     verify ....................................................................6.214ms

field=AESTowerField8b n_vars=20
Start:   generate
End:     generate ..................................................................999.200µs
Start:   commit, n_vars=20
End:     commit, n_vars=20 .........................................................13.271ms
Start:   prove
End:     prove .....................................................................47.881ms
Start:   verify
End:     verify ....................................................................8.168ms

field=AESTowerField32b n_vars=20
Start:   generate
End:     generate ..................................................................4.152ms
Start:   commit, n_vars=20
End:     commit, n_vars=20 .........................................................58.399ms
Start:   prove
End:     prove .....................................................................168.937ms
Start:   verify
End:     verify ....................................................................9.809ms

field=BinaryField1b n_vars=24
Start:   generate
End:     generate ..................................................................1.467ms
Start:   commit, n_vars=24
End:     commit, n_vars=24 .........................................................26.603ms
Start:   prove
End:     prove .....................................................................79.612ms
Start:   verify
End:     verify ....................................................................9.856ms

field=AESTowerField8b n_vars=24
Start:   generate
End:     generate ..................................................................12.968ms
Start:   commit, n_vars=24
End:     commit, n_vars=24 .........................................................298.757ms
Start:   prove
End:     prove .....................................................................636.475ms
Start:   verify
End:     verify ....................................................................12.988ms

field=AESTowerField32b n_vars=24
Start:   generate
End:     generate ..................................................................71.301ms
Start:   commit, n_vars=24
End:     commit, n_vars=24 .........................................................1.256s
Start:   prove
End:     prove .....................................................................2.649s
Start:   verify
End:     verify ....................................................................19.412ms
```

## License

Copyright Irreducible Inc. 2024

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.