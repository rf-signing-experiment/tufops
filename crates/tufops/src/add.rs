//! `tufops add`: hashing local files, comparing them with the metadata, and uploading and adding
//! the new and changed ones in a signing event.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use futures_util::{StreamExt, TryStreamExt, stream};
use tracing::debug;
use tuf::crypto::HashAlgorithm;
use tuf::metadata::{TargetDescription, TargetPath};
use tufops_cloud::open_store;
use tufops_core::publish::{target_object, target_sha256};
use tufops_core::repo::METADATA;
use walkdir::WalkDir;

use crate::event::{EventArgs, slug};
use crate::try_again;

/// A file to add: its target path, where it is locally, and its description.
type LocalFile = (TargetPath, PathBuf, TargetDescription);

/// Target paths, local files and their descriptions to add: a file goes to `to` (or into it
/// when `to` ends in `/`); a directory's files go under `to`, keeping their relative paths.
fn collect_files(from: &Path, to: &str) -> Result<Vec<LocalFile>> {
    if from.is_file() {
        let name = from
            .file_name()
            .and_then(|n| n.to_str())
            .context("bad file name")?;
        let target = if to.ends_with('/') {
            format!("{to}{name}")
        } else {
            to.to_owned()
        };
        return Ok(vec![(
            TargetPath::new(target)?,
            from.to_owned(),
            describe(from)?,
        )]);
    }
    let mut files = vec![];
    for entry in WalkDir::new(from).sort_by_file_name() {
        let entry = entry?;
        if entry.file_type().is_file() {
            let rel = entry.path().strip_prefix(from)?;
            let parts: Vec<_> = rel
                .iter()
                .map(|c| c.to_str().context("non UTF-8 path"))
                .collect::<Result<_>>()?;
            let target = [to.trim_matches('/'), &parts.join("/")].join("/");
            let desc = describe(entry.path())?;
            files.push((
                TargetPath::new(target.trim_start_matches('/'))?,
                entry.into_path(),
                desc,
            ));
        }
    }
    ensure!(!files.is_empty(), "no files in {from:?}");
    Ok(files)
}

/// The length and SHA-256 of `file`, as the repository describes targets.
fn describe(file: &Path) -> Result<TargetDescription> {
    let data = std::fs::read(file).with_context(|| format!("reading {file:?}"))?;
    let desc = TargetDescription::from_slice(&data, &[HashAlgorithm::Sha256])?;
    debug!(file = %file.display(), bytes = desc.length(), "hashed");
    Ok(desc)
}

/// The directory `--to` names, as the start of the target paths in it ("" for the whole
/// repository), or `None` when it names a single file.
fn target_dir(from: &Path, to: &str) -> Option<String> {
    if from.is_file() && !to.ends_with('/') {
        return None;
    }
    let dir = to.trim_matches('/');
    Some(if dir.is_empty() {
        String::new()
    } else {
        format!("{dir}/")
    })
}

/// What `add` changes in the repository.
#[derive(Debug, Default)]
struct Plan {
    /// Files at target paths the repository doesn't list.
    added: Vec<LocalFile>,
    /// Files at target paths the repository lists with another SHA-256.
    changed: Vec<LocalFile>,
    /// How many files the repository already lists with the same SHA-256.
    unchanged: usize,
    /// Listed targets to remove because the files lack them.
    removed: BTreeSet<TargetPath>,
}

impl Plan {
    /// Compares `files` with `listed`, the targets the repository lists. With `delete_in`, a
    /// directory as `target_dir` gives it, the targets in it that `files` lacks are removed.
    fn new(
        listed: &HashMap<TargetPath, TargetDescription>,
        files: Vec<LocalFile>,
        delete_in: Option<&str>,
    ) -> Self {
        let mut plan = Plan::default();
        if let Some(dir) = delete_in {
            let keep: HashSet<_> = files.iter().map(|(path, ..)| path).collect();
            let stale = listed.keys().filter(|p| p.as_str().starts_with(dir));
            plan.removed = stale.filter(|p| !keep.contains(p)).cloned().collect();
        }
        for file in files {
            match listed.get(&file.0) {
                None => plan.added.push(file),
                Some(desc) if target_sha256(desc).ok() != target_sha256(&file.2).ok() => {
                    plan.changed.push(file)
                }
                Some(_) => plan.unchanged += 1,
            }
        }
        plan
    }

    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.changed.is_empty() && self.removed.is_empty()
    }

    /// Lists the changes as under way or, for a dry run, as what would happen.
    fn print(&self, dry_run: bool) {
        let verb = |now, would| if dry_run { would } else { now };
        for (path, ..) in &self.added {
            println!("{} {path}", verb("Adding", "Would add"));
        }
        for (path, ..) in &self.changed {
            println!("{} {path}", verb("Changing", "Would change"));
        }
        for path in &self.removed {
            println!("{} {path}", verb("Removing", "Would remove"));
        }
        if self.unchanged > 0 {
            let s = if self.unchanged == 1 { "" } else { "s" };
            let skip = verb("Skipping", "Would skip");
            println!("{skip} {} unchanged file{s}", self.unchanged);
        }
        if self.is_empty() {
            println!("Nothing to add, change or remove.");
        }
    }
}

/// How many files `add` uploads at once.
const PARALLEL_UPLOADS: usize = 6;

/// Uploads `files` to `storage`, returning their target paths and descriptions. Opens the
/// storage only when there is something to upload.
async fn upload(
    storage: &str,
    files: Vec<LocalFile>,
) -> Result<Vec<(TargetPath, TargetDescription)>> {
    if files.is_empty() {
        return Ok(vec![]);
    }
    let store = &*open_store(storage).await?;
    stream::iter(files)
        .map(|(path, file, desc)| async move {
            let object = target_object(&path, &desc)?;
            println!("Uploading {} as {object}", file.display());
            while let Err(err) = store.put_file(&object, &file).await {
                ensure!(try_again(&err)?, "upload failed");
            }
            anyhow::Ok((path, desc))
        })
        .buffer_unordered(PARALLEL_UPLOADS)
        .try_collect()
        .await
}

/// Adds the files of `from` to the repository at `to`, skipping those it already lists with the
/// same SHA-256. With `delete`, also removes the targets in the `to` directory that `from`
/// lacks. With `dry_run`, only lists the changes, compared with the metadata the event would
/// start from.
pub async fn add(
    dir: &Path,
    from: &Path,
    to: &str,
    delete: bool,
    dry_run: bool,
    event: EventArgs,
    device: Option<u32>,
) -> Result<()> {
    let files = collect_files(from, to)?;
    let delete_in = if delete { target_dir(from, to) } else { None };
    let name = format!("add-{}", slug(to));
    if dry_run {
        let listed = event.preview(dir, &name)?.listed_targets()?;
        Plan::new(&listed, files, delete_in.as_deref()).print(true);
        return Ok(());
    }
    let mut ev = event.open(dir, &name)?;
    let plan = Plan::new(&ev.head.listed_targets()?, files, delete_in.as_deref());
    plan.print(false);
    // Starting over still pushes, to replace the event on the remote.
    if plan.is_empty() && !ev.restart {
        return Ok(());
    }
    let message = match plan.removed.len() {
        0 => format!("Add {to}"),
        1 => format!("Add {to}, removing 1 target"),
        n => format!("Add {to}, removing {n} targets"),
    };
    let files = plan.added.into_iter().chain(plan.changed).collect();
    let targets = upload(&ev.config.storage, files).await?;
    let now = Utc::now();
    ev.head.add_targets(&ev.config, &ev.base, targets, now)?;
    if !plan.removed.is_empty() {
        let removed = |path: &TargetPath| plan.removed.contains(path);
        ev.head.remove_targets(&ev.config, &ev.base, removed, now)?;
    }
    ev.sign_and_finish(&message, &[METADATA], device).await
}
