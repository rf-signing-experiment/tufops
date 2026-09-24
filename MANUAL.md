# tufops manual

tufops runs a [TUF](https://theupdateframework.io) repository from a GitHub repository, in the
style of [tuf-on-ci](https://github.com/theupdateframework/tuf-on-ci):

* The TUF **metadata** lives in git. Every change happens on a `sign/<event>` branch, called a
  **signing event**.
* The **artifacts** (TUF "targets") are not stored in git. They are uploaded straight to cloud
  storage (Google Cloud Storage for now).
* **Offline keys** are YubiKeys held by people. **Online keys** are Cloud KMS keys, used by the
  `tufops` CLI and by CI.
* A **GitHub action** tracks each signing event that needs people in a pull request, which lists
  who still has to sign. A maintainer merges it once every signature is in. Events that only
  online keys sign are merged by CI straight away. On `main`, CI signs `snapshot` and
  `timestamp` and publishes to cloud storage.

Contents:

1. [Concepts](#1-concepts)
2. [Installing the CLI](#2-installing-the-cli)
3. [Setting up a repository](#3-setting-up-a-repository)
4. [Adding and changing files](#4-adding-and-changing-files)
5. [Signing with a YubiKey](#5-signing-with-a-yubikey)
6. [Changing keys and roles](#6-changing-keys-and-roles)
7. [Expiry and automation](#7-expiry-and-automation)
8. [Reference](#8-reference)
9. [Releasing tufops](#9-releasing-tufops)

## 1. Concepts

### Roles

Every repository has the four top-level TUF roles: `root`, `targets`, `snapshot` and
`timestamp`. You can add more roles that `targets` **delegates** a set of paths to, for example a
`firmware` role for `firmware/` signed by YubiKeys and a `nightly` role for `nightly/` signed by
an online key.

A role's keys decide how it is signed:

| Keys | Signed by | When |
|---|---|---|
| all online | Cloud KMS | automatically, by the CLI or CI |
| any offline | people with YubiKeys | in a signing event, until the threshold is met |

`snapshot` and `timestamp` must use online keys. CI signs them on `main`.

### Signing events

A signing event is a `sign/<name>` branch that changes metadata. It goes through these steps:

1. Someone runs `tufops add` or `tufops apply`. The CLI makes the change, signs it with every
   online key it needs, and with your YubiKey if it needs yours. It then pushes the branch.
2. CI works out what the event changes and whose signatures are still missing:
   * If only online keys sign the event, all their signatures are in, and only `metadata/`
     changed, CI merges it into `main`. Online-only changes therefore go live without a pull
     request.
   * Otherwise CI opens a pull request. Its description lists every change and who has and
     hasn't signed, and CI keeps it up to date.
   * Either way, CI sets a `tufops/signatures` status on the event's latest commit. It stays
     pending until every signature is in, so as a required check it blocks merging (§3.2).
3. Signers run `tufops sign` to add their signatures. Each push updates the pull request.
4. When the last signature is in, the status turns green, and a maintainer reviews and merges
   it. CI never merges an event that offline keys sign, or one that changes `tufops.toml`, which
   signatures don't cover.
5. On `main`, CI signs new `snapshot` and `timestamp` versions and publishes.

### What lives where

```
<git repository>
├── tufops.toml               keys and roles (see §8)
├── metadata/
│   ├── root.json             current root
│   ├── root_history/N.root.json   every root version, which clients need
│   ├── targets.json
│   ├── <delegated role>.json
│   ├── snapshot.json
│   └── timestamp.json
└── .github/workflows/tufops.yml

gs://<bucket>/<prefix>/
├── metadata/N.root.json, N.targets.json, N.<role>.json, N.snapshot.json, timestamp.json
└── targets/<dir>/<sha256>.<file name>     artifacts (consistent snapshots)
```

TUF clients use `https://storage.googleapis.com/<bucket>/<prefix>/metadata/` as the metadata URL
and `.../targets/` as the targets URL. They trust `1.root.json`, which you ship with them.

## 2. Installing the CLI

The `tufops` CLI needs `git` (it uses your normal git credentials) and, for YubiKeys, the PC/SC
service. On Debian/Ubuntu install `pcscd` and `libpcsclite-dev`. macOS already has PC/SC.

```sh
cargo install --locked --git https://github.com/rf-signing-experiment/tufops tufops
```

Linux x86-64 binaries are also attached to each release.

Online signing and uploads use Google
[Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials),
for example from `gcloud auth application-default login`.

Run every command from a clone of the TUF repository, or pass `--repo <path>`.

## 3. Setting up a repository

You need a Google Cloud project, an empty GitHub repository (the "TUF repository"), and a
YubiKey for each offline signer.

### 3.1 Google Cloud

```sh
PROJECT=my-project
PROJECT_NUMBER=$(gcloud projects describe $PROJECT --format='value(projectNumber)')
BUCKET=my-tuf-repo
REPO=my-org/my-tuf-repo           # the GitHub TUF repository
SA=tufops-ci@$PROJECT.iam.gserviceaccount.com

# Public bucket that clients download from.
gcloud storage buckets create gs://$BUCKET --project=$PROJECT --location=US \
  --uniform-bucket-level-access
gcloud storage buckets add-iam-policy-binding gs://$BUCKET \
  --member=allUsers --role=roles/storage.objectViewer

# The online key. It must be EC_SIGN_P256_SHA256. HSM protection is recommended.
gcloud kms keyrings create tufops --location=global --project=$PROJECT
gcloud kms keys create online --keyring=tufops --location=global --project=$PROJECT \
  --purpose=asymmetric-signing --default-algorithm=ec-sign-p256-sha256 --protection-level=hsm

# The service account CI uses: it signs with the key and writes to the bucket.
gcloud iam service-accounts create tufops-ci --project=$PROJECT
gcloud kms keys add-iam-policy-binding online --keyring=tufops --location=global \
  --project=$PROJECT --member=serviceAccount:$SA --role=roles/cloudkms.signerVerifier
gcloud storage buckets add-iam-policy-binding gs://$BUCKET \
  --member=serviceAccount:$SA --role=roles/storage.objectAdmin

# Let GitHub Actions act as the service account, but only for workflows running on main.
gcloud iam workload-identity-pools create github --location=global --project=$PROJECT
gcloud iam workload-identity-pools providers create-oidc tufops --project=$PROJECT \
  --location=global --workload-identity-pool=github \
  --issuer-uri=https://token.actions.githubusercontent.com \
  --attribute-mapping=google.subject=assertion.sub,attribute.repository=assertion.repository \
  --attribute-condition="assertion.repository == '$REPO' && assertion.ref == 'refs/heads/main'"
gcloud iam service-accounts add-iam-policy-binding $SA --project=$PROJECT \
  --role=roles/iam.workloadIdentityUser \
  --member=principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github/attribute.repository/$REPO
```

People who run `tufops add` for paths signed by online keys also need
`roles/cloudkms.signerVerifier` on the key and `roles/storage.objectAdmin` on the bucket.
People who only add files that YubiKeys sign need just the bucket role.

### 3.2 GitHub App

CI acts as a GitHub App rather than with the workflow's `GITHUB_TOKEN`, for two reasons: its
pushes must trigger workflows (the merge of a signing event triggers publishing), and it must be
able to push to a protected `main`.

1. Go to **Settings → Developer settings → GitHub Apps → New GitHub App** for your organization
   (or your account).
   * **Name**: for example `my-org-tufops`.
   * **Homepage URL**: the TUF repository's URL.
   * **Webhook**: clear **Active**. tufops does not use webhooks.
   * **Repository permissions**:
     * Contents: **Read and write** (push metadata, merge events, delete event branches)
     * Pull requests: **Read and write** (open and update signing event pull requests)
     * Commit statuses: **Read and write** (the `tufops/signatures` status)
     * Issues: **Read and write** (report failed runs)
     * Metadata: **Read-only** (required by GitHub)
     * Leave everything else at **No access**. In particular it does not need Workflows.
   * **Where can this GitHub App be installed?**: **Only on this account**.
2. After creating it, note the **Client ID** and **Generate a private key**. Keep the `.pem`
   file safe.
3. **Install App**, and choose **Only select repositories** → the TUF repository.
4. In the TUF repository, go to **Settings → Secrets and variables → Actions** and add:
   * Variable `TUFOPS_APP_CLIENT_ID`: the Client ID.
   * Secret `TUFOPS_APP_PRIVATE_KEY`: the full contents of the `.pem` file.
   * Variable `GCP_WORKLOAD_IDENTITY_PROVIDER`:
     `projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github/providers/tufops`.
   * Variable `GCP_SERVICE_ACCOUNT`: `tufops-ci@<PROJECT>.iam.gserviceaccount.com`.
5. Protect `main` under **Settings → Rules → Rulesets → New branch ruleset**:
   * Target: the default branch.
   * Rules: **Restrict deletions**, **Block force pushes**, **Require a pull request before
     merging**, and **Require status checks to pass** with the check `tufops/signatures`. That
     check is what stops a pull request from being merged while signatures are missing. The
     workflow job itself succeeds whenever it did its work, even if signatures are missing.
     Pull requests from branches other than `sign/*` never get the check, so metadata can
     only reach `main` through signing events. Merge any other change (such as a workflow
     update) with a bypass.
   * **Bypass list**: add the tufops App (**Always allow**), so CI can push `snapshot` and
     `timestamp` and merge signing events.

Security notes:

* TUF clients verify every signature themselves. Someone who gains write access to the GitHub
  repository can't forge offline signatures. The worst they can do is delay updates. Online
  keys are a different matter: anything that can run code on `main` in CI can use them, which is
  why the Workload Identity condition above is limited to `refs/heads/main`.
* Keep write access to the TUF repository to the people who need it. Anyone with write access
  can push a `sign/*` branch, and online-only changes merge without review.

### 3.3 YubiKeys

Each offline signer sets up the PIV applet once with
[`ykman`](https://docs.yubico.com/software/yubikey/tools/ykman/). This needs YubiKey 5 firmware
5.3 or later.

```sh
ykman piv access change-pin                  # the default PIN is 123456
ykman piv access change-puk                  # the default PUK is 12345678
ykman piv access change-management-key --generate --protect
ykman piv keys generate --algorithm ECCP256 --pin-policy ALWAYS --touch-policy ALWAYS 9c -
tufops pubkey                                # prints the key in the form tufops.toml takes
```

The signer sends the PEM that `tufops pubkey` prints to a maintainer. It is a public key, so it
is safe to share. To print an online key's PEM, use
`tufops pubkey --online gcpkms:projects/.../cryptoKeyVersions/1`.

### 3.4 The TUF repository

In the new GitHub repository, add `tufops.toml`:

```toml
storage = "gs://my-tuf-repo"          # or gs://bucket/prefix

[keys.alice]
owner = "@alice"                      # GitHub user who holds this YubiKey
public_key = """
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
"""

[keys.bob]
owner = "@bob"
public_key = """..."""

[keys.online]
online = "gcpkms:projects/my-project/locations/global/keyRings/tufops/cryptoKeys/online/cryptoKeyVersions/1"
public_key = """..."""

[roles.root]
keys = ["alice", "bob"]
threshold = 2
expires_days = 365
signing_days = 60

[roles.targets]
keys = ["alice", "bob"]
threshold = 1
expires_days = 365
signing_days = 60

[roles.snapshot]
keys = ["online"]
threshold = 1
expires_days = 365
signing_days = 60

[roles.timestamp]
keys = ["online"]
threshold = 1
expires_days = 2
signing_days = 1

# Delegated roles: any role with `paths`.
[roles.firmware]
paths = ["firmware/"]
keys = ["alice", "bob"]
threshold = 2
expires_days = 365
signing_days = 60

[roles.nightly]
paths = ["nightly/"]
keys = ["online"]
threshold = 1
expires_days = 30
signing_days = 7
```

Then add `.github/workflows/tufops.yml`. Pin the action to a release commit:

```yaml
name: tufops
on:
  push:
    branches: [main, "sign/**"]
  schedule:
    - cron: "17 */6 * * *"      # keeps timestamp fresh; well inside its signing_days
  workflow_dispatch:

permissions:
  contents: read
  id-token: write               # Google Workload Identity Federation

concurrency:
  group: tufops-${{ github.ref }}
  cancel-in-progress: false

jobs:
  tufops:
    runs-on: ubuntu-latest
    steps:
      - uses: rf-signing-experiment/tufops@b0cef4d026a80848cfb90b801f86181afd8ec457 # v0.1.0
        with:
          app-client-id: ${{ vars.TUFOPS_APP_CLIENT_ID }}
          app-private-key: ${{ secrets.TUFOPS_APP_PRIVATE_KEY }}
          gcp-workload-identity-provider: ${{ vars.GCP_WORKLOAD_IDENTITY_PROVIDER }}
          gcp-service-account: ${{ vars.GCP_SERVICE_ACCOUNT }}
```

Commit both files to `main` and push. Then create the first metadata:

```sh
tufops apply --event init
```

This creates `root`, `targets` and the delegated roles on `sign/init`. The CLI signs `nightly`
with the online key, and signs with your YubiKey if it is plugged in and needed. The other
signers run `tufops sign` (§5). When the thresholds are met, a maintainer merges the `sign/init`
pull request, and CI creates `snapshot` and `timestamp` and publishes. Hand `metadata/root_history/1.root.json` to your
clients as their trusted root.

## 4. Adding and changing files

```sh
tufops add --from ./build/fw-1.2.bin --to firmware/fw-1.2.bin
tufops add --from ./build/out/ --to nightly/2026-09-23/        # a whole directory
```

`add`:

1. Checks out the signing event (by default `sign/add-<to>`; pass `--event` to pick one, or to
   add several things to one event). An existing event on the remote is continued.
2. Hashes each file and uploads it to `targets/<dir>/<sha256>.<name>` in the bucket. Clients
   can't see it until metadata that lists it is published.
3. Adds each file to the role whose `paths` match it, or to `targets` if none match.
4. Signs with the online keys those roles need. If your YubiKey is plugged in and needed, it
   shows what you would sign and asks before signing (see §5).
5. Commits and pushes the event, then prints its status.

For a role signed only by online keys, CI merges and publishes straight away. For an offline
role, CI opens a pull request. The signers sign it, then a maintainer merges it.

**Changing a file** is the same command with the same `--to`. The new content replaces the old
entry. The old artifact stays in the bucket, so clients that still have older metadata keep
working.

If an upload or signature fails, tufops shows the error and asks whether to **try again** or
**give up**. You can fix the problem (log in to `gcloud`, re-plug the YubiKey) and continue
without starting over. Nothing is pushed until the end.

## 5. Signing with a YubiKey

When a pull request lists you as a signer:

```sh
tufops status        # every open signing event and who still has to sign it
tufops sign          # sign the ones that need your YubiKey
```

`tufops sign`:

1. Finds the events that need your YubiKey's key and lets you pick which to review, all of them
   by default.
2. For each event, lists every role your key would sign before anything touches the YubiKey.
   For each role it shows the new version and expiry, and every change to its signed metadata:
   targets added, changed or removed (with size and SHA-256), keys and thresholds, delegations
   and their paths. It then asks you to confirm.
3. Only after you confirm does it ask for your PIN, once per session.
4. Signs each role, naming the role and version as it goes. Touch the YubiKey when it blinks.
5. Pushes. CI updates the pull request. Once yours was the last signature needed, a maintainer
   can merge it.

For example:

```
Your YubiKey (@alice, key 7f465af1) is needed to sign this role in sign/add-firmware-fw-1.2.bin:
  firmware  version 3 → 4, expires 2026-12-23 03:33 UTC
    target firmware/fw-1.2.bin added (1048576 bytes, sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08)
Sign? [y/n]
```

On a wrong PIN the prompt tells you how many tries are left. Choose **Try again** to re-enter it.
Choose **Give up** to skip that role. The rest of the event is still pushed.

You can also name events: `tufops sign add-firmware-fw-1.2.bin`.

## 6. Changing keys and roles

Edit `tufops.toml`, then run:

```sh
tufops apply --event rotate-bob     # any event name
```

`apply` carries your uncommitted `tufops.toml` edits onto the event branch. It rewrites the
metadata to match: keys, thresholds, and delegated roles and their paths. Any role whose
metadata changes gets a new version that its keys must sign. It then signs, commits (the
metadata and `tufops.toml`) and pushes like `add`. Typical changes:

* **Add or replace a signer**: add their key under `[keys]` and list it in the roles.
* **Change a threshold**: edit `threshold`.
* **New delegated role**: add a `[roles.<name>]` with `paths`.
* **Remove a delegated role**: delete its section. Its targets go with it.
* **Rotate the online key**: create a new KMS key version and change `online` and `public_key`.
* **Change how long a role is valid**: edit its `expires_days`. `apply` compares it with the
  committed `tufops.toml` and gives the role a new version that expires `expires_days` from now.
  Its `expires` changes, so its keys must sign it. For `snapshot` and `timestamp`, the event only
  changes `tufops.toml`. Once it is merged, CI sees the change against the previous `main`
  commit and signs new versions.
* **Change when new versions are made**: edit `signing_days`. It is not part of the metadata,
  so it needs no signatures, and it takes effect once the event is merged.

A new root version needs signatures from the thresholds of both the old and the new root. The
status shows these as `root` and `root (previous keys)`. Roles whose keys changed get a new
version even if their content didn't, so the new keys sign them.

Because the event changes `tufops.toml`, a maintainer merges its pull request after the
signatures are in.

## 7. Expiry and automation

Each role gets a new version, valid for `expires_days`, whenever it changes. It also gets one
once it is within `signing_days` of expiring:

* **Online roles** (timestamp, snapshot, online delegated roles): CI re-signs them on its
  schedule and publishes.
* **Offline roles**: CI opens a signing event called `sign/refresh` with the new versions, and
  signers sign it like any other.

On every push to `main`, the scheduled runs and manual runs, CI:

1. Signs new online role versions that are due, and new `snapshot` and `timestamp` versions if
   anything they describe changed. It pushes these to `main`.
2. Verifies the whole repository as a client would, from `1.root.json` through timestamp,
   snapshot, targets and delegations, including expiry. It also checks that every target has
   been uploaded.
3. Uploads only the metadata objects that are missing or differ, comparing MD5 digests with
   the bucket. `timestamp.json` goes last.
4. Starts `sign/refresh` if offline roles are due.

If a run fails, CI opens an issue titled "tufops automation failed", or comments on the one
already open.

You can do the online steps by hand from a `main` checkout:

```sh
tufops online --push     # sign new snapshot/timestamp versions if due
tufops publish           # verify and upload
```

## 8. Reference

### `tufops.toml`

| Field | Meaning |
|---|---|
| `storage` | Where to publish: `gs://bucket` or `gs://bucket/prefix`. |
| `[keys.<name>]` | A key. Set exactly one of `owner` or `online`. |
| `owner` | GitHub user (`@name`) holding the key on a YubiKey (PIV slot 9c). |
| `online` | Cloud KMS key version: `gcpkms:projects/…/cryptoKeyVersions/N`. |
| `public_key` | The key's ECDSA P-256 public key as PEM (`tufops pubkey`). |
| `[roles.<name>]` | A role. `root`, `targets`, `snapshot` and `timestamp` are required. |
| `keys`, `threshold` | Which keys sign the role, and how many signatures it needs. |
| `expires_days` | How long each new version is valid. Changing it (with `tufops apply`) starts a new version with the new expiry, which must be signed. |
| `signing_days` | How long before expiry a new version is made. Must be less than `expires_days`. Changing it needs no signatures. |
| `paths` | Delegated roles only: target paths delegated from `targets`. A path ending in `/` covers everything under it. |

Delegations are terminating, and clients try them in alphabetical order of role name. Keep
their `paths` from overlapping.

### CLI

| Command | What it does |
|---|---|
| `tufops status` | Show every open signing event and its signatures. |
| `tufops sign [EVENT…]` | Sign events with your YubiKey. |
| `tufops add --from PATH --to PATH [--event NAME]` | Upload artifacts and add them in a signing event. |
| `tufops apply [--event NAME]` | Update metadata to match `tufops.toml` in a signing event (default `config`). |
| `tufops online [--push]` | On `main`: sign new online role versions that are due. |
| `tufops publish` | Verify the checkout and upload changed metadata. |
| `tufops pubkey [--online URI]` | Print the YubiKey's or a KMS key's public key. |

All commands take `--repo <path>` (default `.`).

### Crates

| Crate | Purpose |
|---|---|
| `tufops-core` | Config, metadata editing, signing status, verification and publishing. No cloud code. |
| `tufops-cloud` | Cloud backends (Google Cloud KMS and Storage) behind the `Signer` and `BlobStore` traits. Add another provider here. |
| `tufops` | The user CLI, including YubiKey signing. |
| `tufops-ci` | The binary the GitHub action runs. |

### Current limitations

* Keys are ECDSA P-256 only. That is the algorithm both Cloud KMS and YubiKey PIV support.
* One level of delegation: roles can only be delegated from `targets`.
* Removing a target has no command yet. Removing a delegated role removes its targets.
* Google Cloud only, though the `BlobStore` and `Signer` traits are where another provider would
  go.

## 9. Releasing tufops

For maintainers of tufops itself:

1. Bump `version` in the workspace `Cargo.toml`, then commit, tag `vX.Y.Z` and push the tag.
   The `release` workflow builds `tufops` and `tufops-ci` for Linux x86-64, attaches them to
   the GitHub release, and prints their SHA-256 sums.
2. In `action.yml`, set `TUFOPS_REPO`, `TUFOPS_VERSION` and `TUFOPS_SHA256` (the
   `tufops-ci-x86_64-unknown-linux-gnu` sum) and commit. That commit is the one users pin in
   their workflow. Pinning the action therefore also pins the exact binary, and the action checks
   its hash before running it.
3. Keep the third-party actions in `action.yml` and `.github/workflows/` on their latest releases,
   pinned by commit hash.
