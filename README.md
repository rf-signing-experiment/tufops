# tufops

The TUF operations service: runs a [TUF](https://theupdateframework.io) repository from GitHub,
modeled on [tuf-on-ci](https://github.com/theupdateframework/tuf-on-ci) and written in Rust.
Metadata lives in git, artifacts live in cloud storage, and changes are signed with YubiKeys
(offline) or Cloud KMS (online) in pull-request-tracked signing events.

* `crates/tufops-core`: config, metadata editing, signing status, verification, publishing
* `crates/tufops-cloud`: Google Cloud KMS and Storage behind provider-neutral traits
* `crates/tufops`: the user CLI (`tufops`), with YubiKey signing
* `crates/tufops-ci`: the binary behind the GitHub action (`action.yml`)

See [MANUAL.md](MANUAL.md) for setup and usage.
