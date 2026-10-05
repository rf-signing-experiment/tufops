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
`firmware` role for the files in `firmware/` signed by YubiKeys and a `nightly` role for those in
`nightly/` signed by an online key.

A role's keys decide how it is signed:

| Keys | Signed by | When |
|---|---|---|
| all online | Cloud KMS | automatically, by the CLI or CI |
| any offline | people with YubiKeys | in a signing event, until the threshold is met |

`snapshot` and `timestamp` must use online keys. CI signs them on `main`. CI holds only their
keys: a role signed by any other online key is signed by whoever runs the CLI with access to
it, so you can keep, say, a release process's key away from CI (§3.1, §7).

### Signing events

A signing event is a `sign/<name>` branch that changes metadata. It goes through these steps:

1. Someone runs `tufops add` or `tufops apply` in a checkout of `main` that is up to date. The
   CLI starts a new event from `main`, named after the change and the time. It makes the change
   in a temporary worktree, so the checkout stays on `main`, signs it with every online key it
   needs, and with your YubiKey if it needs yours. It then pushes the branch.
2. CI works out what the event changes and whose signatures are still missing:
   * If only online keys sign the event, all their signatures are in, and only `metadata/`
     changed, CI merges it into `main`. Online-only changes therefore go live without a pull
     request.
   * Otherwise CI opens a pull request. Its description lists every change and who has and
     hasn't signed, and CI keeps it up to date. Added and changed target files link to their
     uploads in the bucket, so reviewers can download exactly what they are asked to sign.
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
└── .github/workflows/tufops.yml, tufops-event.yml

gs://<bucket>/<prefix>/
├── index.html                    summary page (see below)
├── metadata/N.root.json, N.targets.json, N.<role>.json, N.snapshot.json, timestamp.json
└── targets/<dir>/<sha256>.<file name>     artifacts (consistent snapshots)
```

TUF clients use `https://storage.googleapis.com/<bucket>/<prefix>/metadata/` as the metadata URL
and `.../targets/` as the targets URL. They trust `1.root.json`, which you ship with them.

People can browse the repository at `https://storage.googleapis.com/<bucket>/<prefix>/index.html`.

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

# Let GitHub Actions act as the service account, but only tufops.yml on main, and only for
# its own work on main: signing events also run tufops.yml on main, as workflow_run.
gcloud iam workload-identity-pools create github --location=global --project=$PROJECT
gcloud iam workload-identity-pools providers create-oidc tufops --project=$PROJECT \
  --location=global --workload-identity-pool=github \
  --issuer-uri=https://token.actions.githubusercontent.com \
  --attribute-mapping=google.subject=assertion.sub,attribute.repository=assertion.repository \
  --attribute-condition="assertion.workflow_ref == '$REPO/.github/workflows/tufops.yml@refs/heads/main' && assertion.event_name in ['push', 'schedule', 'workflow_dispatch']"
gcloud iam service-accounts add-iam-policy-binding $SA --project=$PROJECT \
  --role=roles/iam.workloadIdentityUser \
  --member=principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github/attribute.repository/$REPO
```

People who run `tufops add` for paths signed by online keys also need
`roles/cloudkms.signerVerifier` on the key and `roles/storage.objectAdmin` on the bucket.
People who only add files that YubiKeys sign need just the bucket role. For an online key that
CI must not use, create it the same way, but grant the KMS role only to those people, not to
`$SA`.

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
4. In the TUF repository, go to **Settings → Environments → New environment**, and name it
   `tufops`. Under **Deployment branches and tags**, choose **Selected branches and tags** and
   add `main`. Then add the environment secret `TUFOPS_APP_PRIVATE_KEY`: the full contents of
   the `.pem` file. Don't make it a repository secret.
5. Under **Settings → Secrets and variables → Actions**, add the repository variables:
   * `TUFOPS_APP_CLIENT_ID`: the Client ID.
   * `GCP_WORKLOAD_IDENTITY_PROVIDER`:
     `projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github/providers/tufops`.
   * `GCP_SERVICE_ACCOUNT`: `tufops-ci@<PROJECT>.iam.gserviceaccount.com`.
6. Protect `main` under **Settings → Rules → Rulesets → New branch ruleset**:
   * Target: the default branch.
   * Rules: **Restrict deletions**, **Block force pushes**, **Require a pull request before
     merging**, and **Require status checks to pass** with the check `tufops/signatures`. That
     check is what stops a pull request from being merged while signatures are missing. The
     workflow job itself succeeds whenever it did its work, even if signatures are missing.
   * Set the check's source to the tufops App instead of **Any source**. Otherwise anyone with
     write access can set `tufops/signatures` themselves through the API. If the App isn't
     offered yet, come back once CI has set the check on the first signing event (§3.4).
   * **Bypass list**: add the tufops App (**Always allow**), so CI can push `snapshot` and
     `timestamp` and merge signing events. Also add whoever merges changes other than metadata,
     for example the **Repository admin** role, with **For pull requests only**.
7. Under **Settings → General → Pull Requests**, turn on **Automatically delete head
   branches**, so a merged signing event's branch goes away and CI can start the next
   `sign/refresh`. CI also deletes `sign/*` branches whose pull request was merged, in case the
   setting is off.

Security notes:

* TUF clients verify every signature themselves. Someone who gains write access to the GitHub
  repository can't forge offline signatures. The worst they can do is delay updates. Online
  keys are a different matter: anything that can run code on `main` in CI can use them, which is
  why the Workload Identity condition above admits only `tufops.yml`'s runs for `main`.
* The App may push to `main`, so only main's workflow may use its key: that's what the
  `tufops` environment enforces. A push to a `sign/*` branch runs that branch's
  `tufops-event.yml`, which gets nothing. `tufops.yml` then handles the push, running as
  main's version.
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

# Delegated roles, which clients search in this order. `paths` are patterns of the target paths
# each one signs.
[[delegations]]
name = "firmware"
paths = ["firmware/*"]
keys = ["alice", "bob"]
threshold = 2
expires_days = 365
signing_days = 60

[[delegations]]
name = "nightly"
paths = ["nightly/*/*"]                # nightly/<date>/<file>, nightly/latest/<file>
keys = ["online"]
threshold = 1
expires_days = 30
signing_days = 7
```

Then add two workflows.

`.github/workflows/tufops.yml` 

```yaml
name: tufops
on:
  push:
    branches: [main]
  # Pushes to sign/* branches, signalled by tufops-event.yml.
  workflow_run:
    workflows: [tufops-event]
    types: [requested]
    branches: ["sign/**"]
  schedule:
    - cron: "17 */6 * * *"      # keeps timestamp fresh; well inside its signing_days
  workflow_dispatch:

permissions:
  contents: read
  id-token: write               # Google Workload Identity Federation

jobs:
  tufops:
    if: github.event_name != 'workflow_run' || github.event.workflow_run.event == 'push'
    runs-on: ubuntu-latest
    environment: tufops
    concurrency:
      group: tufops-${{ github.event.workflow_run.head_branch || github.ref }}
      cancel-in-progress: false
    steps:
      - uses: rf-signing-experiment/tufops@0000000000000000000000000000000000000000 # vX.X.X
        with:
          app-client-id: ${{ vars.TUFOPS_APP_CLIENT_ID }}
          app-private-key: ${{ secrets.TUFOPS_APP_PRIVATE_KEY }}
          gcp-workload-identity-provider: ${{ vars.GCP_WORKLOAD_IDENTITY_PROVIDER }}
          gcp-service-account: ${{ vars.GCP_SERVICE_ACCOUNT }}
```

`.github/workflows/tufops-event.yml`

```yaml
name: tufops-event
on:
  push:
    branches: ["sign/**"]

permissions: {}

jobs:
  pushed:
    runs-on: ubuntu-latest
    steps:
      - run: "true"
```

Commit these files to `main` and push. Then create the first metadata:

```sh
tufops apply
```

This creates `root`, `targets` and the delegated roles in a signing event, `sign/config-<time>`.
The CLI signs `nightly` with the online key, and signs with your YubiKey if it is plugged in and
needed. The other signers run `tufops sign` (§5). When the thresholds are met, a maintainer
merges its pull request, and CI creates `snapshot` and `timestamp` and publishes. Hand `metadata/root_history/1.root.json` to your
clients as their trusted root.

## 4. Adding and changing files

```sh
tufops add ./build/fw-1.2.bin firmware/fw-1.2.bin
tufops add ./build/out/ nightly/2026-09-23/        # a whole directory
tufops add ./build/out/ nightly/latest/ --delete   # make nightly/latest/ match it
```

`add`:

1. Starts a new signing event, `sign/add-<to>-<time>`, from `main` in a temporary worktree.
2. Hashes each file and compares it with the metadata. Files the repository already lists at
   the same path with the same SHA-256 are skipped. The rest are uploaded to the bucket.
3. Adds each new or changed file to the role whose `paths` match it, or to `targets` if none
   match.
4. Signs with the online keys those roles need. If your YubiKey is plugged in and needed, it
   shows what you would sign and asks before signing (see §5).
5. Commits and pushes the event, then prints its status.

**Mirroring a directory** With `--delete`, any files in the target directory that do not
exist in the source directory are deleted.

**Previewing.** `--dry-run` lists what `add` would add, change and remove.

For a role signed only by online keys, CI merges and publishes straight away. For an offline
role, CI opens a pull request. The signers sign it, then a maintainer merges it.

**Removing files** takes their target paths, not patterns; a path ending in `/` removes
everything under it:

```sh
tufops rm firmware/fw-1.1.bin
tufops rm nightly/2026-09-01/ nightly/2026-09-02/
```

`rm` removes each matching target from whichever role lists it, in a new signing event,
`sign/rm-<first path>-<time>`. It signs and pushes like `add`, and the status lists each removed
target. The uploaded files stay in the bucket, so clients holding older metadata can still
download them.

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
Your YubiKey (@alice, key 7f465af1) is needed to sign this role in sign/add-firmware-fw-1.2.bin-20260923-103312:
  firmware  version 3 → 4, expires 2026-12-23 03:33 UTC
    target firmware/fw-1.2.bin added (1048576 bytes, sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08)
Sign? [y/n]
```

On a wrong PIN the prompt tells you how many tries are left. Choose **Try again** to re-enter it.
Choose **Give up** to skip that role. The rest of the event is still pushed.

You can also name events, as `tufops status` shows them:
`tufops sign add-firmware-fw-1.2.bin-20260923-103312`.

With several YubiKeys plugged in, tufops asks which to use, or you can pick one by serial
number with `--device` (it is printed on the key, and `ykman list --serials` shows it):
`tufops sign --device 12345678`. `--device` works with every command that uses a YubiKey.

## 6. Changing keys and roles

Edit `tufops.toml`, then run:

```sh
tufops apply
```

`apply` copies your uncommitted `tufops.toml` edits into a new event, `sign/config-<time>`, and
leaves them in your checkout: drop them (`git checkout tufops.toml`) before pulling the merged
event. It rewrites the metadata to match: keys, thresholds, and delegated roles and their paths. Any role whose
metadata changes gets a new version that its keys must sign. It then signs, commits (the
metadata and `tufops.toml`) and pushes like `add`. Typical changes:

* **Add or replace a signer**: add their key under `[keys]` and list it in the roles.
* **Change a threshold**: edit `threshold`.
* **New delegated role**: add a `[[delegations]]` entry. Existing targets its paths match,
  including ones in the top-level `targets`, move into the new role, unless a role listed
  before it matches them too.
* **Change a role's paths, or split, rename, reorder or remove roles**: edit `paths`, or
  replace, move or delete the role's entry. Targets are never dropped: each moves to the first
  role whose paths now match it, or to the top-level `targets` if none do, so clients keep
  finding it. For example, replacing `channels` (`channels/*/*`) with `channels-stable`
  (`channels/stable/*`) and `channels-nightly` (`channels/nightly/*`) moves its targets into
  those two, and the rest of them into `targets`. The status summarizes moves per pair of
  roles, as in "3612 targets moved here unchanged from channels". Only targets whose content
  changes are listed individually. The keys of every role gaining or losing targets must sign.
  To remove targets, use `tufops rm` (§4).
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

* **Roles CI signs** (timestamp, snapshot, and roles signed only by their keys): CI re-signs
  them on its schedule and publishes.
* **Other online roles**: CI opens an issue titled "tufops roles need renewing". Someone with
  their keys runs `tufops apply`, which starts and signs the new versions, and CI merges the
  event. `apply` renews every role that is due, so if offline roles are due too,
  merge `sign/refresh` first.
* **Offline roles**: CI opens a signing event called `sign/refresh` with the new versions, and
  signers sign it like any other.

On every push to `main`, the scheduled runs and manual runs, CI:

1. Signs new versions that are due of the roles it signs, and new `snapshot` and `timestamp`
   versions if anything they describe changed. It pushes these to `main`.
2. Verifies the whole repository as a client would, from `1.root.json` through timestamp,
   snapshot, targets and delegations, including expiry. It also checks that every target has
   been uploaded, and that the bucket's `timestamp.json` is not a newer version (or a different
   one of the same version): clients that already have the newer one would reject the older.
3. Uploads only the metadata objects that are missing or differ, comparing MD5 digests with
   the bucket. `timestamp.json` goes last. The summary page `index.html` is uploaded the same
   way, so only when a new tufops version changes it.
4. Deletes `sign/*` branches whose pull request was merged, unless they have gained commits
   since.
5. Starts `sign/refresh` if offline roles are due.
6. Keeps the "tufops roles need renewing" issue open while other online roles are due, and
   closes it once they're renewed.

If a run fails, CI opens an issue titled "tufops automation failed", or comments on the one
already open.

You can do the online steps by hand from a `main` checkout:

```sh
tufops online     # sign new versions of the roles CI signs, if due, and push them
git pull
tufops publish    # verify and upload
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
| `[roles.<name>]` | A top-level role: `root`, `targets`, `snapshot` and `timestamp`, all required. |
| `[[delegations]]` | A role delegated from `targets`, with a `name` and `paths` besides the settings every role has. Clients search them in the order listed. |
| `keys`, `threshold` | Which keys sign the role, and how many signatures it needs. |
| `expires_days` | How long each new version is valid. Changing it (with `tufops apply`) starts a new version with the new expiry, which must be signed. |
| `signing_days` | How long before expiry a new version is made. Must be less than `expires_days`. Changing it needs no signatures. |
| `paths` | Delegated roles only: patterns of the target paths delegated to the role. A pattern matches whole target paths, where `*` matches any characters and `?` any one character, but neither matches `/`: `fw/*` matches `fw/a.bin` but not `fw/beta/a.bin`, which takes `fw/*/*`. Patterns must not start or end with `/`, or contain `[`. |

Delegations are terminating: clients try them in the order `[[delegations]]` lists them, and
stop at the first whose paths match the target. That role is the one the target belongs to.
Roles' paths may match some of the same targets, so list more specific roles first: with
`archive-2026` (`archive/2026/*`) listed before `archive` (`archive/*/*`), `archive/2026/a`
belongs to `archive-2026` and `archive/2025/a` to `archive`. Listed the other way round,
`archive` gets both. Reordering roles moves their targets like any other change to `paths`, and
the status shows the new order.

Patterns match as the TUF specification describes, which is how rust-tuf, python-tuf and go-tuf
match them, except that rust-tuf reads `[` as itself while the others start a character class
with it. So tufops rejects `[`.

### CLI

| Command | What it does |
|---|---|
| `tufops status` | Show every open signing event and its signatures. |
| `tufops sign [EVENT…]` | Sign events with your YubiKey. |
| `tufops add <FROM> <TO> [--delete] [--dry-run]` | Upload new and changed artifacts and add them in a new signing event; `--delete` remove extra files in <TO> |
| `tufops rm PATH…` | Remove targets (a path ending in `/` removes everything under it; paths are not patterns) in a new signing event; their uploads are kept. |
| `tufops apply` | Update metadata to match your `tufops.toml` edits in a new signing event. |
| `tufops online` | Sign new versions that are due of the roles CI signs, and push them to `main`. |
| `tufops publish` | Verify the checkout and upload changed metadata. |
| `tufops pubkey [--online URI]` | Print the YubiKey's or a KMS key's public key. |

All commands take `--repo <path>` (default `.`) and `--device <serial number>`, the YubiKey to
use when several are plugged in. All but `pubkey` need `main` checked out and up to date with
`origin/main`.

To see what tufops does, for example when a command fails in a way you don't understand, set
`TUFOPS_LOG`: `TUFOPS_LOG=tufops=debug tufops sign` logs every git command, storage upload and
signature to stderr. It takes
[`EnvFilter` directives](https://docs.rs/tracing-subscriber/0.3/tracing_subscriber/filter/struct.EnvFilter.html):
`tufops=debug` shows tufops's own logs, and plain `debug` adds those of the libraries it uses,
such as the Google Cloud and GitHub clients. `tufops-ci` reads it too: to debug the automation,
add `TUFOPS_LOG: tufops=debug` to the `env` of the `tufops` job in `tufops.yml`.

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
