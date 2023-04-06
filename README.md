# UniPass-tss-lib

This project is a Rust implementation of {t,n}-threshold ECDSA and EDDSA based on [multi-party-ecdsa](https://github.com/ZenGo-X/multi-party-ecdsa) and [multi-party-eddsa](https://github.com/ZenGo-X/multi-party-eddsa).

## Generating WASM Module

To generate a wasm module, enter the wasm directory and run `wasm-pack build --target web` or `wasm-pack build --target nodejs`.

## Test

To test multi-party eddsa, run the command below:

```sh
cargo test --package tss-eddsa --lib -- tests::tests::test_tss --exact --nocapture
```

To test lindel17, run the command below:

```sh
cargo test --package lindell --lib -- tests::tests::sign --exact --nocapture
```

## License

UniPass-tss-lib is released under the terms of the GPL-3.0 license. See [LICENSE](LICENSE) for more information.