//! `tufops-ci`: the automation the tufops GitHub action runs on a checkout of the repository.
//!
//! On a push to a `sign/*` branch it keeps that signing event's pull request and
//! `tufops/signatures` status up to date, and merges events only online keys sign. On main
//! (pushes, schedule and manual runs) it signs new snapshot and timestamp versions, publishes,
//! starts signing events for offline roles about to expire, and opens an issue for online roles
//! about to expire that it can't sign.

mod markdown;

use std::fmt::Write as _;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::{Parser, Subcommand};
use octocrab::Octocrab;
use octocrab::issues::IssueHandler;
use octocrab::models::issues::Issue;
use octocrab::models::{IssueState, StatusState};
use octocrab::params::State;
use tracing::debug;
use tracing_subscriber::EnvFilter;
use tufops_cloud::open_store;
use tufops_core::git::{Git, MAIN, REMOTE, SIGN_PREFIX};
use tufops_core::publish::publish;
use tufops_core::repo::METADATA;
use tufops_core::{Config, EventStatus, Repo};

/// Signing event CI starts when offline roles are about to expire.
const REFRESH_EVENT: &str = "refresh";
const FAILURE_TITLE: &str = "tufops automation failed";
/// Issue listing online roles about to expire that CI can't sign.
const RENEW_TITLE: &str = "tufops roles need renewing";
/// Commit status on signing events: make it a required check so pull requests missing
/// signatures can't be merged.
const STATUS_CONTEXT: &str = "tufops/signatures";

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// The repository's git checkout.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Handle the branch in `TUFOPS_BRANCH`: a signing event or main.
    Run,
    /// Open an issue about the failed workflow run, or comment on the one already open.
    ReportFailure,
}

struct GitHub {
    client: Octocrab,
    owner: String,
    repo: String,
    /// Link to this workflow run.
    run_url: String,
}

impl GitHub {
    fn from_env() -> Result<Self> {
        let var = |name| std::env::var(name).context(name);
        let repository = var("GITHUB_REPOSITORY")?;
        let (owner, repo) = repository
            .split_once('/')
            .context("bad GITHUB_REPOSITORY")?;
        let optional = |name| var(name).unwrap_or_default();
        let (server, run) = (optional("GITHUB_SERVER_URL"), optional("GITHUB_RUN_ID"));
        Ok(Self {
            client: Octocrab::builder()
                .personal_token(var("GITHUB_TOKEN")?)
                .build()?,
            owner: owner.to_owned(),
            repo: repo.to_owned(),
            run_url: format!("{server}/{repository}/actions/runs/{run}"),
        })
    }

    fn issues(&self) -> IssueHandler<'_> {
        self.client.issues(&self.owner, &self.repo)
    }

    /// Sets the `tufops/signatures` status of commit `sha` with `description`: pending until
    /// every signature is in.
    async fn set_status(&self, sha: &str, status: &EventStatus, description: &str) -> Result<()> {
        let state = if status.complete() {
            StatusState::Success
        } else {
            StatusState::Pending
        };
        debug!(sha, ?state, description, "setting {STATUS_CONTEXT}");
        (self.client.repos(&self.owner, &self.repo))
            .create_status(sha.to_owned(), state)
            .context(STATUS_CONTEXT.to_owned())
            // GitHub limits status descriptions to 140 characters.
            .description(description.chars().take(140).collect())
            .target(self.run_url.clone())
            .send()
            .await?;
        Ok(())
    }

    /// The open issue titled `title`, if any.
    async fn open_issue(&self, title: &str) -> Result<Option<Issue>> {
        let open = (self.issues())
            .list()
            .state(State::Open)
            .per_page(100u8)
            .send()
            .await?;
        let count = open.items.len();
        let issue = (open.items.into_iter()).find(|i| i.title == title && i.pull_request.is_none());
        debug!(title, open = count, found = ?issue.as_ref().map(|i| i.number), "looked for issue");
        Ok(issue)
    }

    /// Updates the description of the open pull request for `branch`, or creates one if `create`.
    async fn update_pr(&self, branch: &str, body: &str, create: bool) -> Result<()> {
        let pulls = self.client.pulls(&self.owner, &self.repo);
        let head = format!("{}:{branch}", self.owner);
        let open = pulls.list().state(State::Open).head(head).send().await?;
        let title = format!("Signing event {branch}");
        let pr = open.items.first().map(|pr| pr.number);
        debug!(?pr, create, "updating the pull request for {branch}");
        match open.items.first() {
            Some(pr) => drop(pulls.update(pr.number).body(body).send().await?),
            None if create => drop(pulls.create(title, branch, MAIN).body(body).send().await?),
            None => {}
        }
        Ok(())
    }

    /// Keeps an issue open listing `roles`, the online roles in their signing period that CI
    /// can't sign, and closes it once there are none.
    async fn report_renewals(&self, repo: &Repo, roles: &[String]) -> Result<()> {
        let issues = self.issues();
        let issue = self.open_issue(RENEW_TITLE).await?;
        if roles.is_empty() {
            if let Some(issue) = issue {
                let close = issues.update(issue.number).state(IssueState::Closed);
                close.send().await?;
            }
            return Ok(());
        }
        let mut body = String::from(
            "CI can't sign these roles. Someone with their keys must renew them before they \
             expire, with `tufops apply --event renew`.\n\n",
        );
        for role in roles {
            let (_, expires) = repo.require_header(role)?;
            let _ = writeln!(body, "- `{role}` expires {}", expires.format("%Y-%m-%d"));
        }
        match issue {
            Some(issue) if issue.body.as_deref() == Some(&body) => {}
            Some(issue) => drop(issues.update(issue.number).body(&body).send().await?),
            None => drop(issues.create(RENEW_TITLE).body(body).send().await?),
        }
        Ok(())
    }

    /// Comments on the open issue about failed runs with a link to this one, or opens the issue.
    async fn report_failure(&self, branch: &str) -> Result<()> {
        let issues = self.issues();
        let body = format!("tufops failed on `{branch}`: {}", self.run_url);
        match self.open_issue(FAILURE_TITLE).await? {
            Some(issue) => drop(issues.create_comment(issue.number, body).await?),
            None => drop(issues.create(FAILURE_TITLE).body(body).send().await?),
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing()?;
    debug!(?cli, "tufops-ci {}", env!("CARGO_PKG_VERSION"));
    let github = GitHub::from_env()?;
    let branch = std::env::var("TUFOPS_BRANCH").context("TUFOPS_BRANCH");
    match cli.command {
        Command::Run => {
            let branch = branch?;
            if let Some(event) = branch.strip_prefix(SIGN_PREFIX) {
                signing_event(&github, &cli.repo, event).await
            } else if branch == MAIN {
                main_branch(&github, &cli.repo).await
            } else {
                bail!("tufops runs on {MAIN} and {SIGN_PREFIX}* branches, not {branch}")
            }
        }
        Command::ReportFailure => github.report_failure(&branch.unwrap_or_default()).await,
    }
}

/// Logs to stderr when `TUFOPS_LOG` is set, filtered by its directives (such as `tufops=debug`).
fn init_tracing() -> Result<()> {
    let directives = std::env::var("TUFOPS_LOG").unwrap_or_default();
    if directives.is_empty() {
        return Ok(());
    }
    let filter = EnvFilter::try_new(&directives).context("invalid TUFOPS_LOG")?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    Ok(())
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
            format!(
                "{branch} conflicts with {MAIN}: start it over with --restart, for example \
                 `tufops apply --event {event} --restart`"
            )
        })?;
        let changed_files = git.changed_files(&main)?;
        if changed_files.is_empty() {
            println!("{branch} changes nothing");
            return Ok(());
        }
        let config = Config::load(dir)?;
        // Only builds clients: this job has no cloud credentials, and needs none for URLs.
        let store = open_store(&config.storage).await?;
        let status = EventStatus::new(&config, &Repo::load_rev(&git, &main)?, &Repo::load(dir)?)?;
        let merge = status.merges_automatically(&changed_files);
        debug!(
            attempt,
            ?changed_files,
            complete = status.complete(),
            offline = status.offline(),
            merge,
            "checked whether {branch} merges automatically"
        );

        let next_step = status.next_step(&changed_files);
        let mut body = String::new();
        markdown::write_event(&mut body, &branch, &status, store.as_ref());
        let _ = write!(body, "\n{next_step}");
        println!("{body}");
        github.set_status(&tip, &status, &next_step).await?;
        // Only events that merge straight away, signed by online keys alone, skip the pull
        // request.
        github.update_pr(&branch, &body, !merge).await?;
        if !merge {
            return Ok(());
        }
        match git.push(MAIN, false) {
            Ok(_) => return git.run(&["push", REMOTE, "--delete", &branch]).map(drop),
            Err(err) if attempt < 3 => eprintln!("retrying: {err:#}"),
            Err(err) => return Err(err),
        }
    }
    unreachable!()
}

/// Signs new versions that are due of the roles CI signs, publishes, and starts a signing event
/// for offline roles in their signing period. Online roles in their signing period that CI can't
/// sign are listed in an issue instead.
async fn main_branch(github: &GitHub, dir: &Path) -> Result<()> {
    let git = Git::new(dir);
    let config = Config::load(dir)?;
    // The config before the latest change to main, which the current metadata was built from.
    let previous = Config::load_rev(&git, "HEAD^")
        .inspect_err(|err| debug!("no previous config: {err:#}"))
        .ok();
    let changed = tufops_cloud::update_online(&git, &config, previous.as_ref()).await?;
    debug!(?changed, "updated the online roles");
    if !changed.is_empty()
        && let Err(err) = git.push(MAIN, false)
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
    let mut head = repo.clone();
    let expiring = head.apply_config(&config, previous.as_ref(), &repo, Utc::now())?;
    // CI renewed the online roles it signs above, so these are ones it can't sign.
    let (online, offline): (Vec<_>, Vec<_>) =
        expiring.into_iter().partition(|r| config.online_only(r));
    debug!(?online, ?offline, "roles in their signing period");
    if !offline.is_empty() && !git.remote_events()?.iter().any(|e| e == REFRESH_EVENT) {
        let branch = git.checkout_event(REFRESH_EVENT, false)?;
        repo.with_roles_from(&head, &offline).save(dir)?;
        let message = format!("Start new versions of {}", offline.join(", "));
        git.commit(&message, &[METADATA])?;
        git.push(&branch, false)?;
        println!("Started {branch} for {offline:?}; its workflow run opens the pull request");
    }
    github.report_renewals(&repo, &online).await
}
