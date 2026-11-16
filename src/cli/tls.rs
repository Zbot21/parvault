//! `parvault tls show | export | rotate`: the edge's self-signed certificate (B-1, L-81,
//! A-TLS-6; `v0.5.6` track A).
//!
//! `v0.5.6` T0 stub: every subcommand is refused (`reject.not_built_yet`) until track A builds
//! it on `parvault::edge_tls`.

use parvault::config::TlsAction;
use std::path::Path;

pub(crate) fn run(action: TlsAction, data_dir: &Path) -> anyhow::Result<()> {
    let _ = data_dir;
    let entry = match action {
        TlsAction::Show => "tls show",
        TlsAction::Export { out: _ } => "tls export",
        TlsAction::Rotate => "tls rotate",
    };
    Err(parvault::seam::not_built_yet(parvault::seam::Unbuilt { track: "A", entry }).into())
}
