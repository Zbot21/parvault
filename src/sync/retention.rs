//! Retention of folder versions (B-154 C25-C29): keep 3 recent plus 3 daily by default; client
//! ceilings 50, 90 and 52 are refused, not clamped; a warning above 1.25x the policy maximum (C43,
//! C44).
//!
//! `v0.5.6` track B2. Empty at T0 (the seam commit creates the module so no shared file is edited
//! later); the track fills it in.
