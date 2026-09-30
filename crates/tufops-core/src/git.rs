//! A thin wrapper around the `git` command line, so the user's credentials and settings apply.

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use tracing::debug;

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
        let command = args.join(" ");
        debug!("git {command}");
        let out = Command::new("git")
            .current_dir(&self.dir)
            .args(args)
            .output()
            .with_context(|| format!("running git {command}"))?;
        // Some callers expect failures and check the status themselves, dropping stderr.
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            debug!(stderr = stderr.trim(), "git {command}: {}", out.status);
        }
        Ok(out)
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

    /// Files that `HEAD` changed since it branched off `rev`.
    pub fn changed_files(&self, rev: &str) -> Result<Vec<String>> {
        let out = self.run(&["diff", "--name-only", &format!("{rev}...HEAD")])?;
        Ok(out.lines().map(str::to_owned).collect())
    }

    pub fn fetch(&self) -> Result<()> {
        self.run(&["fetch", "--prune", REMOTE]).map(drop)
    }

    /// Fetches, then checks that main is checked out and matches the remote main branch, which
    /// every change starts from.
    pub fn check_main(&self) -> Result<()> {
        self.fetch()?;
        let branch = self.run(&["rev-parse", "--abbrev-ref", "HEAD"])?;
        ensure!(branch == MAIN, "check out {MAIN} first");
        let remote = Self::remote_ref(MAIN);
        ensure!(
            self.run(&["rev-parse", "HEAD"])? == self.run(&["rev-parse", &remote])?,
            "{MAIN} differs from {remote}: bring it up to date first, for example with `git pull`"
        );
        Ok(())
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

    /// The last commit `a` and `b` have in common.
    pub fn merge_base(&self, a: &str, b: &str) -> Result<String> {
        self.run(&["merge-base", a, b])
    }

    /// Checks out `rev`, with a detached `HEAD`, in a new worktree in a temporary directory.
    pub fn worktree(&self, rev: &str) -> Result<Worktree> {
        let name = format!("tufops-{}-{}", std::process::id(), rev.replace('/', "-"));
        let dir = std::env::temp_dir().join(name);
        let path = dir.to_str().context("non UTF-8 temporary directory")?;
        self.run(&["worktree", "add", "--quiet", "--detach", path, rev])?;
        Ok(Worktree {
            git: Git::new(dir),
            repo: Git::new(&self.dir),
        })
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

    /// Pushes `HEAD` to `branch` on the remote, which must be new or behind it.
    pub fn push(&self, branch: &str) -> Result<()> {
        let refspec = format!("HEAD:refs/heads/{branch}");
        self.run(&["push", "--quiet", REMOTE, &refspec]).map(drop)
    }
}

/// A temporary worktree from `Git::worktree`, used like any checkout and removed when dropped.
pub struct Worktree {
    git: Git,
    /// The repository's own checkout.
    repo: Git,
}

impl Deref for Worktree {
    type Target = Git;

    fn deref(&self) -> &Git {
        &self.git
    }
}

impl Drop for Worktree {
    fn drop(&mut self) {
        let dir = self.git.dir.to_string_lossy();
        // Failures are logged, and at worst leave a stale worktree behind.
        let _ = self.repo.run(&["worktree", "remove", "--force", &dir]);
    }
}
