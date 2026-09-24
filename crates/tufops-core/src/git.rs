//! A thin wrapper around the `git` command line, so the user's credentials and settings apply.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};

use crate::repo::METADATA;

/// Prefix of the branches that hold signing events.
pub const SIGN_PREFIX: &str = "sign/";
pub const MAIN: &str = "main";
pub const REMOTE: &str = "origin";

pub struct Git {
    dir: PathBuf,
}

impl Git {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn output(&self, args: &[&str]) -> Result<std::process::Output> {
        Command::new("git")
            .current_dir(&self.dir)
            .args(args)
            .output()
            .with_context(|| format!("running git {}", args.join(" ")))
    }

    /// Runs git, returning its trimmed standard output.
    pub fn run(&self, args: &[&str]) -> Result<String> {
        let out = self.output(args)?;
        ensure!(
            out.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }

    /// Contents of `path` at `rev`, or `None` if it does not exist there.
    pub fn show(&self, rev: &str, path: &str) -> Result<Option<Vec<u8>>> {
        let spec = format!("{rev}:{path}");
        if !self.output(&["cat-file", "-e", &spec])?.status.success() {
            return Ok(None);
        }
        let out = self.output(&["cat-file", "blob", &spec])?;
        ensure!(out.status.success(), "git cat-file blob {spec} failed");
        Ok(Some(out.stdout))
    }

    /// Paths of all files under `dir` at `rev`.
    pub fn ls(&self, rev: &str, dir: &str) -> Result<Vec<String>> {
        let out = self.run(&["ls-tree", "-r", "--name-only", rev, "--", dir])?;
        Ok(out.lines().map(str::to_owned).collect())
    }

    /// Files that differ between `rev` and `HEAD`.
    pub fn changed_files(&self, rev: &str) -> Result<Vec<String>> {
        let out = self.run(&["diff", "--name-only", rev, "HEAD"])?;
        Ok(out.lines().map(str::to_owned).collect())
    }

    /// Whether `paths` have no uncommitted changes.
    pub fn is_clean(&self, paths: &[&str]) -> Result<bool> {
        Ok(self
            .run(&[&["status", "--porcelain", "--"], paths].concat())?
            .is_empty())
    }

    pub fn current_branch(&self) -> Result<String> {
        self.run(&["rev-parse", "--abbrev-ref", "HEAD"])
    }

    pub fn fetch(&self) -> Result<()> {
        self.run(&["fetch", "--prune", REMOTE]).map(drop)
    }

    /// Signing event names (without the `sign/` prefix) that exist on the remote.
    pub fn remote_events(&self) -> Result<Vec<String>> {
        let refs = format!("refs/remotes/{REMOTE}/{SIGN_PREFIX}");
        let out = self.run(&["for-each-ref", "--format=%(refname)", &refs])?;
        Ok(out
            .lines()
            .filter_map(|r| r.strip_prefix(&refs))
            .map(str::to_owned)
            .collect())
    }

    pub fn remote_ref(branch: &str) -> String {
        format!("{REMOTE}/{branch}")
    }

    pub fn rev_exists(&self, rev: &str) -> Result<bool> {
        let spec = format!("{rev}^{{commit}}");
        Ok(self
            .output(&["rev-parse", "--verify", "--quiet", &spec])?
            .status
            .success())
    }

    /// Checks out signing event `event`. An event on the remote is continued, with the remote
    /// main branch merged into it so that edits build on the current metadata; if that merge
    /// conflicts, the event is stale (merged or abandoned) and this fails. An event not on the
    /// remote, or any event with `restart`, starts from the remote main branch, and pushing it
    /// replaces whatever the remote held. Uncommitted edits to `tufops.toml` are carried along;
    /// uncommitted metadata is not allowed.
    pub fn checkout_event(&self, event: &str, restart: bool) -> Result<String> {
        ensure!(
            self.is_clean(&[METADATA])?,
            "{METADATA}/ has uncommitted changes"
        );
        self.fetch()?;
        let branch = format!("{SIGN_PREFIX}{event}");
        let remote = Self::remote_ref(&branch);
        let main = Self::remote_ref(MAIN);
        let local = self.rev_exists(&format!("refs/heads/{branch}"))?;
        if restart || !self.rev_exists(&remote)? {
            // A local branch left over from an event that has since been merged starts afresh.
            let merged = self.output(&["merge-base", "--is-ancestor", &branch, &main])?;
            ensure!(
                restart || !local || merged.status.success(),
                "{branch} has commits that are not on {REMOTE}: push it, or pass --restart to \
                 discard them"
            );
            self.run(&["checkout", "--quiet", "-B", &branch, &main])?;
            return Ok(branch);
        }
        // Check the merge before touching the working tree, which may hold tufops.toml edits.
        let stale = format!(
            "{branch} conflicts with {MAIN}, so it was probably merged or abandoned: use another \
             event name, or pass --restart to start it over from {MAIN}, discarding its changes \
             and signatures"
        );
        let merge = self.output(&["merge-tree", "--write-tree", &remote, &main])?;
        ensure!(merge.status.success(), "{stale}");
        if local {
            self.run(&["checkout", "--quiet", &branch])?;
            self.run(&["merge", "--quiet", "--ff-only", &remote])?;
        } else {
            self.run(&["checkout", "--quiet", "-b", &branch, &remote])?;
        }
        let message = format!("Merge {MAIN} into {branch}");
        if let Err(err) = self.run(&["merge", "--quiet", "--no-edit", "-m", &message, &main]) {
            let _ = self.run(&["merge", "--abort"]);
            return Err(err.context(stale));
        }
        Ok(branch)
    }

    /// Commits all changes under `paths`, returning false if there were none.
    pub fn commit(&self, message: &str, paths: &[&str]) -> Result<bool> {
        self.run(&[&["add", "--all", "--"], paths].concat())?;
        let diff = self.output(&[&["diff", "--cached", "--quiet", "--"], paths].concat())?;
        if diff.status.success() {
            return Ok(false);
        }
        self.run(&[&["commit", "--quiet", "-m", message, "--"], paths].concat())?;
        Ok(true)
    }

    /// Pushes `HEAD` to `branch` on the remote. With `replace`, it overwrites the branch even if
    /// that discards commits, as long as the branch hasn't changed since the last fetch.
    pub fn push(&self, branch: &str, replace: bool) -> Result<()> {
        let refspec = format!("HEAD:refs/heads/{branch}");
        let force = if replace {
            "--force-with-lease"
        } else {
            "--no-force"
        };
        self.run(&["push", "--quiet", force, REMOTE, &refspec])
            .map(drop)
    }
}
