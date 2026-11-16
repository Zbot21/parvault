//! `parvault tls show | export | rotate`: the edge's self-signed certificate (B-1, L-81,
//! A-TLS-6; `v0.5.6` track A), on `parvault::edge_tls`.

use parvault::config::TlsAction;
use parvault::edge_tls::{colon_hex, CertInfo};
use std::path::Path;

pub(crate) fn run(action: TlsAction, data_dir: &Path) -> anyhow::Result<()> {
    match action {
        TlsAction::Show => {
            let info = parvault::edge_tls::show(data_dir)?;
            print_info(data_dir, &info);
        }
        TlsAction::Export { out } => {
            let info = parvault::edge_tls::export(data_dir, &out)?;
            println!("wrote {} (certificate only, no key)", out.display());
            println!(
                "file SHA-256 (certutil -hashfile {} SHA256): {}",
                out.display(),
                hex::encode(info.export_sha256)
            );
        }
        TlsAction::Rotate => {
            let info = parvault::edge_tls::rotate(data_dir)?;
            println!("issued a new edge key and certificate; restart the daemon to serve it");
            println!(
                "every client must register the new certificate again (`parvault tls export --out webdav.crt`)"
            );
            print_info(data_dir, &info);
        }
    }
    Ok(())
}

fn print_info(data_dir: &Path, info: &CertInfo) {
    println!(
        "file:                {}",
        data_dir.join(parvault::edge_tls::EDGE_TLS_FILE).display()
    );
    println!("certificate SHA-256: {}", colon_hex(&info.cert_sha256));
    println!("webdav.crt SHA-256:  {}", hex::encode(info.export_sha256));
    println!("pin (curl):          {}", info.curl_pin());
    println!(
        "SANs:                {}",
        if info.sans.is_empty() {
            "(not recorded)".to_string()
        } else {
            info.sans.join(", ")
        }
    );
    match info.not_after_unix_secs {
        Some(t) => {
            let (y, m, d) = parvault::edge_tls::civil_from_days((t / 86_400) as i64);
            println!("expires:             {y:04}-{m:02}-{d:02} (UTC)");
        }
        None => println!("expires:             (not recorded)"),
    }
}
