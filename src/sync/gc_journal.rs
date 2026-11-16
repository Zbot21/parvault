//! The owner's version-GC journal (B-154 C3, C5): new roots are journalled before `place_stripe`;
//! an offline host's entry is retried with backoff and abandoned after 30 days.
//!
//! `v0.5.6` track B2. Empty at T0 (the seam commit creates the module so no shared file is edited
//! later); the track fills it in.
