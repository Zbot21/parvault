//! The daemon's fetch scheduler (L-72, arch056b S1-S7; `v0.5.6` track C): foreground reads
//! (WebDAV, FUSE, IPC) preempt the in-daemon scavenger at stripe admission in `gateway::engine`,
//! with [`SLOTS`] = 8 slots of which a scavenger holds at most `SLOTS - 1`, so the last slot is
//! always foreground's (S2). A queued scavenger is aged in after [`AGING_N`] = 8 foreground grants
//! passed it over (S3).
//!
//! The class comes from the entry point only (S4): a thread is foreground unless the in-daemon
//! scavenger runs it inside [`run_as_scavenger`]. Nothing read from IPC or the wire sets it, so
//! every IPC `FetchRange` is foreground. Daemon-local only; no cancellation.
//!
//! [`counters`] is what live status reads (track D, S7).

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

/// Stripe slots (S2).
pub const SLOTS: u8 = 8;
/// Foreground grants a queued scavenger may be passed over before it is aged in (S3).
pub const AGING_N: u8 = 8;

/// Scheduler counters exported to live status (S7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchSchedCounters {
    /// `defer.scavenger_preempted`: scavenger admissions deferred for a foreground read.
    pub scavenger_preempted: u64,
    /// Block-cache misses (one per single-flight fetch, B-24).
    pub cache_misses: u64,
    /// Stripe fetches admitted by the scheduler (each reads the block store or the network).
    pub network_fetches: u64,
    /// Foreground and scavenger requests waiting now.
    pub foreground_queued: u64,
    pub scavenger_queued: u64,
}

/// Who a fetch is for (S4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchClass {
    Foreground,
    Scavenger,
}

/// One admission decision (claim `L72-SCHED`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotDecision {
    GrantForeground,
    GrantScavenger,
    /// Nothing is granted now.
    Wait,
}

/// Claim `L72-SCHED` (`@guard`): the next grant, given the queue lengths, the free slots, the
/// scavengers in flight and how many foreground grants have passed the oldest queued scavenger.
/// - no slot free: wait;
/// - aging (S3): a scavenger queued and passed over `AGING_N` times starts if it may hold a slot;
/// - otherwise a queued foreground is granted whenever a slot is free; with a scavenger queued
///   that grant defers it (`defer.scavenger_preempted`, the second value);
/// - a scavenger starts only with no foreground queued and fewer than `SLOTS - 1` in flight.
pub const fn fetch_slot_decision(
    fg_queued: u8,
    bg_queued: u8,
    slots_free: u8,
    bg_in_flight: u8,
    bg_skipped: u8,
) -> (SlotDecision, Option<&'static str>) {
    if slots_free == 0 {
        return (SlotDecision::Wait, None);
    }
    let bg_may_hold = bg_in_flight < SLOTS - 1;
    if bg_queued > 0 && bg_may_hold && bg_skipped >= AGING_N {
        return (SlotDecision::GrantScavenger, None);
    }
    if fg_queued > 0 {
        if bg_queued > 0 {
            return (
                SlotDecision::GrantForeground,
                Some("defer.scavenger_preempted"),
            );
        }
        return (SlotDecision::GrantForeground, None);
    }
    if bg_queued > 0 && bg_may_hold {
        return (SlotDecision::GrantScavenger, None);
    }
    (SlotDecision::Wait, None)
}

/// The scheduler's state (the transition the Kani harnesses check).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedState {
    pub fg_queued: u8,
    pub bg_queued: u8,
    pub fg_in_flight: u8,
    pub bg_in_flight: u8,
    pub bg_skipped: u8,
}

impl SchedState {
    pub const fn slots_free(&self) -> u8 {
        SLOTS.saturating_sub(self.fg_in_flight.saturating_add(self.bg_in_flight))
    }

    /// Applies one decision; returns it with the new state.
    pub const fn step(self) -> (SlotDecision, Self) {
        let (d, _) = fetch_slot_decision(
            self.fg_queued,
            self.bg_queued,
            self.slots_free(),
            self.bg_in_flight,
            self.bg_skipped,
        );
        let mut s = self;
        match d {
            SlotDecision::GrantForeground => {
                s.fg_queued -= 1;
                s.fg_in_flight += 1;
                // Capped at `AGING_N`: past it the scavenger is due at its next chance.
                if s.bg_queued > 0 && s.bg_skipped < AGING_N {
                    s.bg_skipped += 1;
                }
            }
            SlotDecision::GrantScavenger => {
                s.bg_queued -= 1;
                s.bg_in_flight += 1;
                s.bg_skipped = 0;
            }
            SlotDecision::Wait => {}
        }
        (d, s)
    }
}

static SCAVENGER_PREEMPTED: AtomicU64 = AtomicU64::new(0);
static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);

/// Records one block-cache miss (the VFS calls it once per single-flight fetch, B-24).
pub fn note_cache_miss() {
    CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
}

/// The current counters of the daemon's scheduler (S7).
pub fn counters() -> FetchSchedCounters {
    let g = global();
    let (fg, bg) = g.queued();
    FetchSchedCounters {
        scavenger_preempted: SCAVENGER_PREEMPTED.load(Ordering::Relaxed),
        cache_misses: CACHE_MISSES.load(Ordering::Relaxed),
        network_fetches: g.admitted.load(Ordering::Relaxed),
        foreground_queued: fg as u64,
        scavenger_queued: bg as u64,
    }
}

#[derive(Clone)]
struct ScavengerCtx {
    promoted: Arc<AtomicBool>,
}

thread_local! {
    static CTX: RefCell<Option<ScavengerCtx>> = const { RefCell::new(None) };
}

/// Runs `f` as the scavenger (S4: only the in-daemon scavenger calls this). Its admissions are
/// scavenger-class until `promoted` is set (S6), then foreground.
pub fn run_as_scavenger<R>(promoted: Arc<AtomicBool>, f: impl FnOnce() -> R) -> R {
    struct Reset(Option<ScavengerCtx>);
    impl Drop for Reset {
        fn drop(&mut self) {
            let prev = self.0.take();
            CTX.with(|c| *c.borrow_mut() = prev);
        }
    }
    let prev = CTX.with(|c| c.borrow_mut().replace(ScavengerCtx { promoted }));
    let _reset = Reset(prev);
    f()
}

/// The promotion flag of the scavenger running on this thread, if any (a B-24 single-flight
/// entry keeps it so a joining foreground reader can promote the fetch, S6).
pub fn current_promotion_flag() -> Option<Arc<AtomicBool>> {
    CTX.with(|c| c.borrow().as_ref().map(|s| Arc::clone(&s.promoted)))
}

/// The class of a fetch started on this thread now.
pub fn current_class() -> FetchClass {
    CTX.with(|c| match c.borrow().as_ref() {
        Some(s) if !s.promoted.load(Ordering::Acquire) => FetchClass::Scavenger,
        _ => FetchClass::Foreground,
    })
}

struct Waiter {
    id: u64,
    promoted: Option<Arc<AtomicBool>>,
}

#[derive(Default)]
struct Inner {
    fg: VecDeque<Waiter>,
    bg: VecDeque<Waiter>,
    fg_in_flight: u8,
    bg_in_flight: u8,
    bg_skipped: u8,
    next_id: u64,
}

impl Inner {
    fn state(&self) -> SchedState {
        SchedState {
            fg_queued: self.fg.len().min(u8::MAX as usize) as u8,
            bg_queued: self.bg.len().min(u8::MAX as usize) as u8,
            fg_in_flight: self.fg_in_flight,
            bg_in_flight: self.bg_in_flight,
            bg_skipped: self.bg_skipped,
        }
    }

    /// Moves promoted scavenger waiters to the foreground queue (S6).
    fn apply_promotions(&mut self) {
        let mut i = 0;
        while i < self.bg.len() {
            let p = self.bg[i]
                .promoted
                .as_ref()
                .is_some_and(|f| f.load(Ordering::Acquire));
            if p {
                if let Some(w) = self.bg.remove(i) {
                    self.fg.push_back(w);
                }
            } else {
                i += 1;
            }
        }
    }
}

/// A slot held for one stripe fetch; dropping it frees the slot.
pub struct SlotPermit<'a> {
    sched: &'a FetchScheduler,
    class: FetchClass,
}

impl Drop for SlotPermit<'_> {
    fn drop(&mut self) {
        let mut g = self.sched.inner.lock().unwrap_or_else(|e| e.into_inner());
        match self.class {
            FetchClass::Foreground => g.fg_in_flight = g.fg_in_flight.saturating_sub(1),
            FetchClass::Scavenger => g.bg_in_flight = g.bg_in_flight.saturating_sub(1),
        }
        drop(g);
        self.sched.cv.notify_all();
    }
}

impl SlotPermit<'_> {
    pub const fn class(&self) -> FetchClass {
        self.class
    }
}

/// The stripe admission gate (S2). One per daemon ([`global`]); tests build their own.
#[derive(Default)]
pub struct FetchScheduler {
    inner: Mutex<Inner>,
    cv: Condvar,
    admitted: AtomicU64,
    /// The S5 mutant: arrival order with no foreground priority and no scavenger cap.
    no_priority: bool,
}

/// The daemon's scheduler. `PARVAULT_TEST_SCHED_NO_PRIORITY=1` in the daemon's environment
/// builds the S5 mutant, so the real-binary accept test can show it fails without the priority.
pub fn global() -> &'static FetchScheduler {
    static G: OnceLock<FetchScheduler> = OnceLock::new();
    G.get_or_init(|| {
        if std::env::var("PARVAULT_TEST_SCHED_NO_PRIORITY").as_deref() == Ok("1") {
            tracing::warn!(
                "PARVAULT_TEST_SCHED_NO_PRIORITY=1: test-only switch, foreground reads get no priority over the scavenger"
            );
            FetchScheduler::without_priority()
        } else {
            FetchScheduler::new()
        }
    })
}

impl FetchScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// A scheduler with the priority removed (the S5 mutant).
    pub fn without_priority() -> Self {
        Self {
            no_priority: true,
            ..Self::default()
        }
    }

    /// Queue lengths now (foreground, scavenger).
    pub fn queued(&self) -> (usize, usize) {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (g.fg.len(), g.bg.len())
    }

    /// In flight now (foreground, scavenger).
    pub fn in_flight(&self) -> (u8, u8) {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (g.fg_in_flight, g.bg_in_flight)
    }

    /// Sets a promotion flag and moves its queued waiters to the foreground queue (S6).
    pub fn promote(&self, flag: &AtomicBool) {
        flag.store(true, Ordering::Release);
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.apply_promotions();
        drop(g);
        self.cv.notify_all();
    }

    /// Admits one stripe fetch of this thread's class ([`current_class`]), blocking until the
    /// decision grants it.
    pub fn admit(&self) -> SlotPermit<'_> {
        match current_class() {
            FetchClass::Scavenger => self.admit_as(FetchClass::Scavenger, current_promotion_flag()),
            FetchClass::Foreground => self.admit_as(FetchClass::Foreground, None),
        }
    }

    /// [`Self::admit`] with an explicit class (unit tests).
    pub fn admit_as(&self, class: FetchClass, promoted: Option<Arc<AtomicBool>>) -> SlotPermit<'_> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let id = g.next_id;
        g.next_id = g.next_id.wrapping_add(1);
        let w = Waiter { id, promoted };
        match class {
            FetchClass::Foreground => g.fg.push_back(w),
            FetchClass::Scavenger => g.bg.push_back(w),
        }
        self.cv.notify_all();
        loop {
            g.apply_promotions();
            let granted = if self.no_priority {
                Self::grant_fifo(&mut g, id)
            } else {
                Self::grant_priority(&mut g, id)
            };
            if let Some(class) = granted {
                drop(g);
                self.admitted.fetch_add(1, Ordering::Relaxed);
                self.cv.notify_all();
                return SlotPermit { sched: self, class };
            }
            g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn grant_priority(g: &mut Inner, id: u64) -> Option<FetchClass> {
        let st = g.state();
        let (_, defer) = fetch_slot_decision(
            st.fg_queued,
            st.bg_queued,
            st.slots_free(),
            st.bg_in_flight,
            st.bg_skipped,
        );
        let (d, next) = st.step();
        let (queue_head, class) = match d {
            SlotDecision::GrantForeground => (g.fg.front().map(|w| w.id), FetchClass::Foreground),
            SlotDecision::GrantScavenger => (g.bg.front().map(|w| w.id), FetchClass::Scavenger),
            SlotDecision::Wait => return None,
        };
        if queue_head != Some(id) {
            return None;
        }
        match class {
            FetchClass::Foreground => {
                g.fg.pop_front();
            }
            FetchClass::Scavenger => {
                g.bg.pop_front();
            }
        }
        g.fg_in_flight = next.fg_in_flight;
        g.bg_in_flight = next.bg_in_flight;
        g.bg_skipped = next.bg_skipped;
        if let Some(code) = defer {
            let n = SCAVENGER_PREEMPTED.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n.is_multiple_of(256) {
                tracing::info!(
                    code,
                    count = n,
                    "fetch_sched: a scavenger fetch was deferred"
                );
            }
        }
        Some(class)
    }

    fn grant_fifo(g: &mut Inner, id: u64) -> Option<FetchClass> {
        if g.fg_in_flight.saturating_add(g.bg_in_flight) >= SLOTS {
            return None;
        }
        let oldest_fg = g.fg.front().map(|w| w.id);
        let oldest_bg = g.bg.front().map(|w| w.id);
        let oldest = match (oldest_fg, oldest_bg) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if oldest != Some(id) {
            return None;
        }
        if oldest_fg == Some(id) {
            g.fg.pop_front();
            g.fg_in_flight += 1;
            Some(FetchClass::Foreground)
        } else {
            g.bg.pop_front();
            g.bg_in_flight += 1;
            Some(FetchClass::Scavenger)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn decision_table() {
        assert_eq!(fetch_slot_decision(1, 1, 0, 0, 0).0, SlotDecision::Wait);
        let (d, defer) = fetch_slot_decision(1, 1, 1, 0, 0);
        assert_eq!(d, SlotDecision::GrantForeground);
        assert!(defer.is_some(), "a queued scavenger is deferred");
        assert_eq!(
            fetch_slot_decision(1, 0, 1, 0, 0),
            (SlotDecision::GrantForeground, None)
        );
        assert_eq!(
            fetch_slot_decision(0, 1, 1, 0, 0).0,
            SlotDecision::GrantScavenger
        );
        assert_eq!(
            fetch_slot_decision(0, 1, 1, SLOTS - 1, 0).0,
            SlotDecision::Wait
        );
        assert_eq!(
            fetch_slot_decision(1, 1, 1, 0, AGING_N).0,
            SlotDecision::GrantScavenger
        );
        assert_eq!(
            fetch_slot_decision(1, 1, 1, SLOTS - 1, AGING_N).0,
            SlotDecision::GrantForeground
        );
    }

    /// S3, the aging unit test: with foreground always queued, a queued scavenger starts
    /// within N+1 grants.
    #[test]
    fn aging_starts_a_scavenger_within_n_plus_1_grants() {
        let mut s = SchedState {
            fg_queued: 200,
            bg_queued: 1,
            fg_in_flight: 0,
            bg_in_flight: 0,
            bg_skipped: 0,
        };
        let mut grants = 0;
        loop {
            let (d, n) = s.step();
            s = n;
            grants += 1;
            match d {
                SlotDecision::GrantScavenger => break,
                // Each foreground fetch completes at once, so a slot is always free.
                SlotDecision::GrantForeground => s.fg_in_flight -= 1,
                SlotDecision::Wait => panic!("a slot was free"),
            }
        }
        assert_eq!(grants, AGING_N as usize + 1);
    }

    /// S2 on the live gate: scavengers alone never take the last slot.
    #[test]
    fn scavengers_leave_the_last_slot_free() {
        let sched = FetchScheduler::new();
        let permits: Vec<_> = (0..SLOTS - 1)
            .map(|_| sched.admit_as(FetchClass::Scavenger, None))
            .collect();
        assert_eq!(sched.in_flight(), (0, SLOTS - 1));
        std::thread::scope(|sc| {
            let s2 = &sched;
            let h = sc.spawn(move || {
                let _p = s2.admit_as(FetchClass::Scavenger, None);
            });
            std::thread::sleep(Duration::from_millis(50));
            assert_eq!(sched.queued(), (0, 1), "the 8th scavenger waits");
            let fg = sched.admit_as(FetchClass::Foreground, None);
            assert_eq!(fg.class(), FetchClass::Foreground);
            drop(fg);
            drop(permits);
            h.join().unwrap();
        });
    }

    /// The S5 mutant lets an 8th scavenger take the last slot.
    #[test]
    fn the_mutant_has_no_scavenger_cap() {
        let sched = FetchScheduler::without_priority();
        let permits: Vec<_> = (0..SLOTS)
            .map(|_| sched.admit_as(FetchClass::Scavenger, None))
            .collect();
        assert_eq!(sched.in_flight(), (0, SLOTS));
        drop(permits);
    }

    /// S6: a queued scavenger waiter whose flag is set moves to the foreground queue.
    #[test]
    fn promotion_moves_a_queued_scavenger_to_foreground() {
        let sched = FetchScheduler::new();
        let held: Vec<_> = (0..SLOTS - 1)
            .map(|_| sched.admit_as(FetchClass::Scavenger, None))
            .collect();
        let flag = Arc::new(AtomicBool::new(false));
        std::thread::scope(|sc| {
            let f2 = Arc::clone(&flag);
            let s2 = &sched;
            let h = sc.spawn(move || s2.admit_as(FetchClass::Scavenger, Some(f2)).class());
            std::thread::sleep(Duration::from_millis(50));
            assert_eq!(sched.queued(), (0, 1));
            sched.promote(&flag);
            assert_eq!(h.join().unwrap(), FetchClass::Foreground);
        });
        drop(held);
    }

    #[test]
    fn class_comes_from_the_entry_point() {
        assert_eq!(current_class(), FetchClass::Foreground);
        let flag = Arc::new(AtomicBool::new(false));
        run_as_scavenger(Arc::clone(&flag), || {
            assert_eq!(current_class(), FetchClass::Scavenger);
            flag.store(true, Ordering::Release);
            assert_eq!(current_class(), FetchClass::Foreground);
        });
        assert_eq!(current_class(), FetchClass::Foreground);
    }
}
