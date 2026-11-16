//! The encrypted genesis backup bundle (B-169, K1-K12): Argon2id with a random salt, then
//! HKDF-SHA256 (`parvault-ring-backup-v1`), XChaCha20-Poly1305, a fixed length-exact header that is
//! all AAD.
//!
//! `v0.5.6` track E. Empty at T0 (the seam commit creates the module so no shared file is edited
//! later); the track fills it in.
