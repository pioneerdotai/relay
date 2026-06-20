use anyhow::Result;
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};
use vergen::{vergen, Config};

fn main() -> Result<()> {
    vergen(Config::default())?;
    emit_git_metadata();
    Ok(())
}

fn emit_git_metadata() {
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_else(|| ".".into()));

    if manifest_dir.join(".git").exists() {
        println!(
            "cargo:rerun-if-changed={}",
            manifest_dir.join(".git/HEAD").display()
        );
    }

    if let Some(version) = git_output(
        &manifest_dir,
        ["describe", "--tags", "--always", "--dirty=-dirty"],
    ) {
        emit_env("VERGEN_GIT_SEMVER_LIGHTWEIGHT", version);
    }

    if let Some(sha) = git_output(&manifest_dir, ["rev-parse", "HEAD"]).or_else(github_sha) {
        emit_env("VERGEN_GIT_SHA", sha);
    }

    if let Some(timestamp) = git_output(&manifest_dir, ["show", "-s", "--format=%cI", "HEAD"]) {
        emit_env("VERGEN_GIT_COMMIT_TIMESTAMP", timestamp);
    }

    if let Some(branch) = git_branch(&manifest_dir).or_else(github_ref_name) {
        emit_env("VERGEN_GIT_BRANCH", branch);
    }
}

fn git_branch(manifest_dir: &Path) -> Option<String> {
    let branch = git_output(manifest_dir, ["rev-parse", "--abbrev-ref", "HEAD"])?;
    if branch == "HEAD" {
        None
    } else {
        Some(branch)
    }
}

fn git_output<const N: usize>(manifest_dir: &Path, args: [&str; N]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(manifest_dir)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    non_empty(value)
}

fn github_sha() -> Option<String> {
    env::var("GITHUB_SHA").ok().and_then(non_empty)
}

fn github_ref_name() -> Option<String> {
    env::var("GITHUB_REF_NAME").ok().and_then(non_empty)
}

fn non_empty(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn emit_env(key: &str, value: String) {
    println!("cargo:rustc-env={key}={value}");
}
