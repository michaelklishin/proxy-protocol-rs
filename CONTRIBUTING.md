# Contributing

## Guidelines

The contribution process is straightforward:

 * Fork the repository
 * Create a topic branch
 * Implement, test, document your changes
 * Push your changes to your fork
 * Create a pull request to merge your changes into the main repository

## Running Tests

While tests support the standard `cargo test` option, another option
for running tests is [`cargo nextest`](https://nexte.st/).

### Run All Tests

```shell
cargo nextest run --all-features
```

### Run Only Unit Tests

```shell
cargo nextest run --all-features -E 'binary(unit)'
```

### Run Only Property-Based Tests

```shell
cargo nextest run --all-features -E 'binary(proptests)'
```

### Run a Specific Test

```shell
cargo nextest run --all-features -E 'test(=test_name_here)'
```

## Running Benchmarks

```shell
cargo bench
```
