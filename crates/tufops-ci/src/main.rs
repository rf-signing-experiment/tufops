//! `tufops-ci`: the automation the tufops GitHub action runs on a checkout of the repository.
//!
//! On a push to a `sign/*` branch it keeps that signing event's pull request and
//! `tufops/signatures` status up to date, and merges events only online keys sign. On main (pushes, schedule and manual runs) it signs
//! new snapshot and timestamp versions, publishes, and starts signing events for offline roles
//! about to expire.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use octocrab::Octocrab;
use octocrab::models::StatusState;
use octocrab::params::State;
use tufops_cloud::{open_store, public_url};
use tufops_core::git::{Git, MAIN, REMOTE, SIGN_PREFIX};
use tufops_core::publish::publish;
use tufops_core::repo::METADATA;
use tufops_core::status::{Change, RoleStatus};
use tufops_core::{Config, EventStatus, Repo};

/// Signing event CI starts when offline roles are about to expire.
const REFRESH_EVENT: &str = "refresh";
const FAILURE_TITLE: &str = "tufops automation failed";
/// Commit status on signing events: make it a required check so pull requests missing
/// signatures can't be merged.
const STATUS_CONTEXT: &str = "tufops/signatures";

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// The repository's git checkout.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Handle the branch in `GITHUB_REF_NAME`: a signing event or main.
    Run,
    /// Open an issue about the failed workflow run, or comment on the one already open.
    ReportFailure,
}

struct GitHub {
    client: Octocrab,
    owner: String,
    repo: String,
}

impl GitHub {
    fn from_env() -> Result<Self> {
        let token = std::env::var("GITHUB_TOKEN").context("GITHUB_TOKEN")?;
        let repository = std::env::var("GITHUB_REPOSITORY").context("GITHUB_REPOSITORY")?;
        let (owner, repo) = repository
            .split_once('/')
            .context("bad GITHUB_REPOSITORY")?;
        let client = Octocrab::builder().personal_token(token).build()?;
        Ok(Self {
            client,
            owner: owner.to_owned(),
            repo: repo.to_owned(),
        })
    }

    /// Sets the `tufops/signatures` status of commit `sha`: pending until every signature is in.
    async fn set_status(&self, sha: &str, status: &EventStatus) -> Result<()> {
        let (state, description) = if status.complete() {
            (StatusState::Success, "All signatures are in".to_owned())
        } else {
            let waiting: Vec<_> = status.waiting_for().into_iter().collect();
            (
                StatusState::Pending,
                format!("Waiting for {}", waiting.join(", ")),
            )
        };
        let var = |name| std::env::var(name).unwrap_or_default();
        let run = format!(
            "{}/{}/actions/runs/{}",
            var("GITHUB_SERVER_URL"),
            var("GITHUB_REPOSITORY"),
            var("GITHUB_RUN_ID")
        );
        // GitHub limits status descriptions to 140 characters.
        let description = description.chars().take(140).collect();
        (self.client.repos(&self.owner, &self.repo))
            .create_status(sha.to_owned(), state)
            .context(STATUS_CONTEXT.to_owned())
            .description(description)
            .target(run)
            .send()
            .await?;
        Ok(())
    }

    /// Updates the description of the open pull request for `branch`, or creates one if `create`.
    async fn update_pr(&self, branch: &str, body: &str, create: bool) -> Result<()> {
        let pulls = self.client.pulls(&self.owner, &self.repo);
        let head = format!("{}:{branch}", self.owner);
        let open = pulls.list().state(State::Open).head(head).send().await?;
        match open.items.first() {
            Some(pr) => drop(pulls.update(pr.number).body(body).send().await?),
            None if create => drop(
                pulls
                    .create(format!("Signing event {branch}"), branch, MAIN)
                    .body(body)
                    .send()
                    .await?,
            ),
            None => {}
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let github = GitHub::from_env()?;
    match cli.command {
        Command::Run => {
            let branch = std::env::var("GITHUB_REF_NAME").context("GITHUB_REF_NAME")?;
            if let Some(event) = branch.strip_prefix(SIGN_PREFIX) {
                signing_event(&github, &cli.repo, event).await
            } else if branch == MAIN {
                main_branch(&cli.repo).await
            } else {
                bail!("tufops runs on {MAIN} and {SIGN_PREFIX}* branches, not {branch}")
            }
        }
        Command::ReportFailure => report_failure(&github).await,
    }
}

/// Merges main into the checked out signing event (without pushing that merge back), so the
/// status reflects what merging the event would publish. Sets the event's
/// `tufops/signatures` status, then merges it into main if `merges_automatically` allows,
/// and otherwise updates its pull request.
async fn signing_event(github: &GitHub, dir: &Path, event: &str) -> Result<()> {
    let git = Git::new(dir);
    let branch = format!("{SIGN_PREFIX}{event}");
    let main = Git::remote_ref(MAIN);
    let tip = git.run(&["rev-parse", "HEAD"])?;
    // Another run may move main between our merge and push; then merge again.
    for attempt in 1.. {
        git.fetch()?;
        git.run(&["checkout", "--quiet", "-B", &branch, &tip])?;
        git.run(&["merge", "--no-edit", &main]).with_context(|| {
            format!("{branch} conflicts with {MAIN}; start it again from {MAIN}")
        })?;
        let changed_files = git.changed_files(&main)?;
        if changed_files.is_empty() {
            println!("{branch} changes nothing");
            return Ok(());
        }
        let config = Config::load(dir)?;
        let status = EventStatus::new(&config, &Repo::load_rev(&git, &main)?, &Repo::load(dir)?)?;
        let merge = status.merges_automatically(&changed_files);

        let mut body = format!(
            "## Signing event `{branch}`\n\n{}\n",
            markdown(&status, &config.storage)?
        );
        let waiting: Vec<_> = status.waiting_for().into_iter().collect();
        body.push_str(&if !status.complete() {
            format!(
                "Waiting for signatures from {}. Signers: check out the repository and run \
                 `tufops sign`.",
                waiting.join(", ")
            )
        } else if merge {
            "All signatures are in: merging.".to_owned()
        } else {
            "All signatures are in: a maintainer can now review and merge this pull request."
                .to_owned()
        });
        println!("{body}");
        github.set_status(&tip, &status).await?;
        // Only events that merge straight away, signed by online keys alone, skip the pull
        // request.
        github.update_pr(&branch, &body, !merge).await?;
        if !merge {
            return Ok(());
        }
        match git.run(&["push", REMOTE, &format!("HEAD:refs/heads/{MAIN}")]) {
            Ok(_) => return git.run(&["push", REMOTE, "--delete", &branch]).map(drop),
            Err(err) if attempt < 3 => eprintln!("retrying: {err:#}"),
            Err(err) => return Err(err),
        }
    }
    unreachable!()
}

/// Signs new online role versions that are due, publishes, and starts a signing event for
/// offline roles in their signing period.
async fn main_branch(dir: &Path) -> Result<()> {
    let git = Git::new(dir);
    let config = Config::load(dir)?;
    // The config before the latest change to main, which the current metadata was built from.
    let previous = Config::load_rev(&git, "HEAD^").ok();
    let changed = tufops_cloud::update_online(&config, previous.as_ref(), dir).await?;
    if git.commit(&format!("Update {}", changed.join(", ")), &[METADATA])?
        && let Err(err) = git.push(MAIN)
    {
        // If main moved on, the run for the newer commit does this work instead.
        git.fetch()?;
        if git.run(&["rev-parse", "HEAD~1"])? != git.run(&["rev-parse", &Git::remote_ref(MAIN)])? {
            println!("{MAIN} moved on ({err:#}); leaving the work to the newer run");
            return Ok(());
        }
        return Err(err);
    }

    let repo = Repo::load(dir)?;
    let store = open_store(&config.storage).await?;
    let uploaded = publish(&repo, store.as_ref()).await?;
    println!("Published {} objects: {uploaded:?}", uploaded.len());

    git.fetch()?;
    if git.remote_events()?.iter().any(|e| e == REFRESH_EVENT) {
        return Ok(());
    }
    let mut head = repo.clone();
    let expiring = head.apply_config(&config, previous.as_ref(), &repo, Utc::now())?;
    if !expiring.is_empty() {
        let branch = git.checkout_event(REFRESH_EVENT)?;
        head.save(dir)?;
        git.commit(
            &format!("Start new versions of {}", expiring.join(", ")),
            &[METADATA],
        )?;
        git.push(&branch)?;
        println!("Started {branch} for {expiring:?}; its workflow run opens the pull request");
    }
    Ok(())
}

async fn report_failure(github: &GitHub) -> Result<()> {
    let var = |name| std::env::var(name).unwrap_or_default();
    let run = format!(
        "{}/{}/actions/runs/{}",
        var("GITHUB_SERVER_URL"),
        var("GITHUB_REPOSITORY"),
        var("GITHUB_RUN_ID")
    );
    let body = format!("tufops failed on `{}`: {run}", var("GITHUB_REF_NAME"));
    let issues = github.client.issues(&github.owner, &github.repo);
    let open = issues
        .list()
        .state(State::Open)
        .per_page(100u8)
        .send()
        .await?;
    match open
        .items
        .iter()
        .find(|i| i.title == FAILURE_TITLE && i.pull_request.is_none())
    {
        Some(issue) => drop(issues.create_comment(issue.number, body).await?),
        None => drop(issues.create(FAILURE_TITLE).body(body).send().await?),
    }
    Ok(())
}

/// The signing status as markdown for the pull request, linking target files to their uploads
/// in `storage`.
fn markdown(status: &EventStatus, storage: &str) -> Result<String> {
    let mut out =
        String::from("| Role | Version | Expires | Signatures | Signed by | Waiting for |\n");
    out.push_str("|---|---|---|---|---|---|\n");
    let names = |keys: &[tufops_core::status::Key]| {
        let names: Vec<_> = keys.iter().map(|k| k.name.as_str()).collect();
        if names.is_empty() {
            "-".to_owned()
        } else {
            names.join(", ")
        }
    };
    for role in &status.roles {
        let (version, expires) = version(role);
        for req in &role.requirements {
            let _ = writeln!(
                out,
                "| {}{} | {} | {} | {} {} of {} | {} | {} |",
                role.role,
                if req.previous_root {
                    " (previous keys)"
                } else {
                    ""
                },
                version,
                expires,
                if req.met() { "✅" } else { "⏳" },
                req.signed.len(),
                req.threshold,
                names(&req.signed),
                names(&req.unsigned),
            );
        }
    }
    for role in status.roles.iter().filter(|r| !r.changes.is_empty()) {
        let _ = writeln!(out, "\n**Changes to {}**\n", role.role);
        for change in &role.changes {
            let _ = match change {
                Change::Target {
                    path,
                    kind,
                    file: Some(file),
                } => writeln!(
                    out,
                    "- target [`{path}`](<{}>) {kind} ({} bytes, sha256 `{}`)",
                    public_url(storage, &file.object)?,
                    file.length,
                    file.sha256
                ),
                Change::Target {
                    path,
                    kind,
                    file: None,
                } => writeln!(out, "- target `{path}` {kind}"),
                Change::Other(text) => writeln!(out, "- {text}"),
            };
        }
    }
    Ok(out)
}

/// The version and expiry columns: what main has, and what the event changes them to.
fn version(role: &RoleStatus) -> (String, String) {
    let date = |d: &DateTime<Utc>| d.format("%Y-%m-%d").to_string();
    match role.base {
        Some((version, expires)) if version != role.version => (
            format!("{version} → {}", role.version),
            format!("{} → {}", date(&expires), date(&role.expires)),
        ),
        _ => (role.version.to_string(), date(&role.expires)),
    }
}
