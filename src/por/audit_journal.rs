//! The PoR audit journal (B-147, G5): `por_audit_journal.bin` (tagged, atomic) holds the absolute
//! post-values of `por_passes` and `por_failures`, never deltas; at start a value is applied only
//! if the current one is lower.
//!
//! `v0.5.6` track B1. Empty at T0 (the seam commit creates the module so no shared file is edited
//! later); the track fills it in.
