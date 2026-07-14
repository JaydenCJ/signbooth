// signbooth — a local artifact-signing daemon: private keys stay in one
// audited process, callers sign via a loopback API under per-caller policy.
//
// version:    0.1.0
// author:     JaydenCJ
// license:    MIT
// repository: https://github.com/JaydenCJ/signbooth
// keywords:   signing, ed25519, supply-chain, provenance, policy, audit, daemon
//
// Zero runtime dependencies: standard library only.
module github.com/JaydenCJ/signbooth

go 1.22
