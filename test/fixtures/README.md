# Test Fixtures

This directory contains deterministic, synthetic test fixtures for the `zk-age-gate` test suite.

## Privacy and Synthetic Data Policy

1. **Zero Real Personal Data**: No real personal identifiers, passport numbers, dates of birth, or individual identities are ever used. All credentials are synthesized programmatically.
2. **Ephemeral Prover Inputs**: Real local proving executes within ephemeral memory and temporary directories that are immediately erased after proof generation.
3. **Reproducible Test Vectors**: Fixtures provide deterministic proof and public input outputs generated using synthetic door-partner keys and sample accounts (e.g., standard Foundry test accounts).
4. **Security Notice**: Never copy production door partner keys or real attendee identity credentials into this directory.
