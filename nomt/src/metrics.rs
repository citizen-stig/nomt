//! Metrics collection.
//!
//! Counters and timers are striped: every thread adds to its own cache-line-aligned stripe and
//! readers sum the stripes. Threads updating one shared atomic would make its cache line bounce
//! between cores on every update, which costs on the order of a hundred nanoseconds per update
//! under contention, comparable to an in-memory value read.
//!
//! What remains is an uncontended atomic add per counter update, and two clock reads per timed
//! operation (tens of nanoseconds in total). This is negligible next to I/O, but not next to a
//! value read served from memory: with [`MetricsLevel::Full`], such reads are a few percent
//! slower. [`MetricsLevel::Io`] only collects metrics updated once per disk read, and does not
//! time value reads.

use std::{
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const METRIC_NOT_COLLECTED: &str = "Metric is not collected at the configured metrics level";

/// Which metrics to collect. Each level collects everything the levels below it collect.
///
/// Getters of metrics not collected at the configured level panic; see
/// `Metrics::metrics_level`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum MetricsLevel {
    /// Collect no metrics.
    #[default]
    Off,
    /// Collect the metrics updated once per disk read: page and leaf cache misses
    /// (`get_page_cache_misses`, `get_leaf_cache_misses`), reads of the hash-table and leaf files
    /// (`get_ht_reads`, `get_ln_reads`) and the page fetch time (`get_page_fetch_time`).
    ///
    /// Their cost is negligible next to the reads themselves, so this level is meant to stay
    /// enabled in production. It shows how much disk I/O the database does and how long page
    /// loads take, but not cache hit ratios or the latency of value reads.
    Io,
    /// Collect all metrics. On top of [`MetricsLevel::Io`], this counts every page and leaf cache
    /// lookup (`get_page_requests`, `get_leaf_cache_requests`) and times every value read
    /// (`get_value_fetch_time`).
    ///
    /// These are updated on paths which do no I/O. Timing value reads makes in-memory reads a
    /// few percent slower.
    Full,
}

/// Metrics collector, if active, it provides Counters and Timers.
///
/// Collection costs an atomic add per counted event, and two clock reads per timed operation.
/// See the module documentation.
#[derive(Clone)]
pub struct Metrics {
    /// `None` if the level is [`MetricsLevel::Off`].
    metrics: Option<Arc<ActiveMetrics>>,
    level: MetricsLevel,
}

/// Metrics that can be collected during execution
#[derive(PartialEq, Eq, Hash)]
pub enum Metric {
    /// Counter of merkle page requests served by the page cache.
    ///
    /// Only requests not already answered by the session overlay reach the page cache. Pages below
    /// an elided child are never requested from the page cache: they are reconstructed from
    /// beatree leaves, which show up in [`Metric::LeafCacheRequests`] instead.
    PageRequests,
    /// Counter of page requests cache misses over all page requests.
    ///
    /// This is not a count of disk reads: a miss on a page whose load is already in flight joins
    /// that load, and a miss on a page absent from the hash-table needs no read at all. Disk reads
    /// are counted by [`Metric::HtReads`].
    PageCacheMisses,
    /// Timer used to record average page fetch time: from the first read of a merkle page load
    /// from the hash-table, after a page cache miss, until the page is found, including all
    /// probes. Loads of pages which turn out not to exist are not recorded, nor are the loads
    /// made when opening the database (the root page and page cache prepopulation).
    PageFetchTime,
    /// Timer used to record average value fetch time during reads.
    ///
    /// Recorded by `Session::read`. The two clock reads around each read add tens of nanoseconds,
    /// which is a few percent of a value read served from memory.
    ValueFetchTime,
    /// Counter of beatree leaf cache lookups. Leaves are looked up when reading values, when
    /// seeking leaf nodes or reconstructing elided merkle pages, during the beatree update of a
    /// commit and when loading prior values for rollback.
    LeafCacheRequests,
    /// Counter of beatree leaf cache lookups which missed. Every miss leads to a read of the `ln`
    /// file, counted by [`Metric::LnReads`].
    LeafCacheMisses,
    /// Counter of page reads issued to the hash-table (`ht`) file, which stores merkle pages.
    /// A single page load may take several reads when probing the hash-table. This includes the
    /// reads made when opening the database, notably page cache prepopulation.
    HtReads,
    /// Counter of page reads issued to the beatree leaf (`ln`) file, which stores leaves and
    /// overflow value pages.
    LnReads,
}

/// Number of stripes. Threads are assigned to stripes round-robin, so up to this many threads
/// never share a stripe.
const STRIPES: usize = 32;

/// The slots of a stripe: one per counter, and a count and a sum per timer.
#[derive(Clone, Copy)]
enum Slot {
    PageRequests,
    PageCacheMisses,
    LeafCacheRequests,
    LeafCacheMisses,
    HtReads,
    LnReads,
    PageFetchCount,
    PageFetchSum,
    ValueFetchCount,
    ValueFetchSum,
}

const NUM_SLOTS: usize = Slot::ValueFetchSum as usize + 1;

/// The slots updated by one group of threads, on cache lines of their own.
#[repr(align(128))]
struct Stripe([AtomicU64; NUM_SLOTS]);

struct ActiveMetrics {
    stripes: Box<[Stripe]>,
}

impl Metric {
    /// The lowest level at which this metric is collected.
    #[inline]
    fn level(&self) -> MetricsLevel {
        match self {
            Metric::PageCacheMisses
            | Metric::LeafCacheMisses
            | Metric::HtReads
            | Metric::LnReads
            | Metric::PageFetchTime => MetricsLevel::Io,
            Metric::PageRequests | Metric::LeafCacheRequests | Metric::ValueFetchTime => {
                MetricsLevel::Full
            }
        }
    }

    fn counter_slot(&self) -> Slot {
        match self {
            Metric::PageRequests => Slot::PageRequests,
            Metric::PageCacheMisses => Slot::PageCacheMisses,
            Metric::LeafCacheRequests => Slot::LeafCacheRequests,
            Metric::LeafCacheMisses => Slot::LeafCacheMisses,
            Metric::HtReads => Slot::HtReads,
            Metric::LnReads => Slot::LnReads,
            _ => panic!("Specified metric is not a Counter"),
        }
    }

    /// The count and sum slots of a timer.
    fn timer_slots(&self) -> (Slot, Slot) {
        match self {
            Metric::PageFetchTime => (Slot::PageFetchCount, Slot::PageFetchSum),
            Metric::ValueFetchTime => (Slot::ValueFetchCount, Slot::ValueFetchSum),
            _ => panic!("Specified metric is not a Timer"),
        }
    }
}

impl ActiveMetrics {
    fn new() -> Self {
        ActiveMetrics {
            stripes: (0..STRIPES)
                .map(|_| Stripe(std::array::from_fn(|_| AtomicU64::new(0))))
                .collect(),
        }
    }

    /// The stripe of the current thread.
    fn stripe(&self) -> &Stripe {
        static NEXT_STRIPE: AtomicUsize = AtomicUsize::new(0);
        thread_local! {
            static STRIPE: usize = NEXT_STRIPE.fetch_add(1, Ordering::Relaxed) % STRIPES;
        }
        &self.stripes[STRIPE.with(|i| *i)]
    }

    fn add(&self, slot: Slot) {
        self.stripe().0[slot as usize].fetch_add(1, Ordering::Relaxed);
    }

    fn add_duration(&self, (count, sum): (Slot, Slot), duration: Duration) {
        let stripe = self.stripe();
        stripe.0[count as usize].fetch_add(1, Ordering::Relaxed);
        stripe.0[sum as usize].fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
    }

    fn load(&self, slot: Slot) -> u64 {
        self.stripes
            .iter()
            .map(|stripe| stripe.0[slot as usize].load(Ordering::Relaxed))
            .sum()
    }

    fn mean(&self, (count, sum): (Slot, Slot)) -> Option<u64> {
        self.load(sum).checked_div(self.load(count))
    }
}

/// Records the time passed since its creation when dropped.
struct TimerGuard<'a> {
    metrics: &'a ActiveMetrics,
    slots: (Slot, Slot),
    start: Instant,
}

impl Drop for TimerGuard<'_> {
    fn drop(&mut self) {
        self.metrics.add_duration(self.slots, self.start.elapsed());
    }
}

impl Metrics {
    /// Returns a Metrics object collecting the metrics of the given level.
    pub fn new(level: MetricsLevel) -> Self {
        Self {
            metrics: (level > MetricsLevel::Off).then(|| Arc::new(ActiveMetrics::new())),
            level,
        }
    }

    /// The level of metrics being collected.
    pub fn metrics_level(&self) -> MetricsLevel {
        self.level
    }

    /// Whether the given metric is collected at the configured level.
    #[inline]
    pub(crate) fn collects(&self, metric: &Metric) -> bool {
        metric.level() <= self.level
    }

    /// The active metrics, if the given metric is collected.
    #[inline]
    fn collecting(&self, metric: &Metric) -> Option<&ActiveMetrics> {
        if self.collects(metric) {
            self.metrics.as_deref()
        } else {
            None
        }
    }

    /// Increase the Counter specified by the input, if it is collected at the configured level.
    ///
    /// panics if the specified [`Metric`] is not a Counter
    pub fn count(&self, metric: Metric) {
        if let Some(metrics) = self.collecting(&metric) {
            metrics.add(metric.counter_slot());
        }
    }

    /// Returns a guard that, when dropped, will record the time passed since creation.
    /// Returns `None`, without reading the clock, if the timer is not collected at the configured
    /// level.
    ///
    /// panics if the specified [`Metric`] is not a Timer
    pub fn record<'a>(&'a self, metric: Metric) -> Option<impl Drop + 'a> {
        self.collecting(&metric).map(|metrics| TimerGuard {
            metrics,
            slots: metric.timer_slots(),
            start: Instant::now(),
        })
    }

    /// Record a duration measured by the caller, for operations which do not fit a scope guard,
    /// such as asynchronous loads. Ignored if the timer is not collected at the configured level.
    ///
    /// panics if the specified [`Metric`] is not a Timer
    pub fn record_duration(&self, metric: Metric, duration: Duration) {
        if let Some(metrics) = self.collecting(&metric) {
            metrics.add_duration(metric.timer_slots(), duration);
        }
    }

    /// Print collected metrics to stdout
    pub fn print(&self) {
        let Some(ref metrics) = self.metrics else {
            println!("Metrics collection was not activated");
            return;
        };
        let full = self.level >= MetricsLevel::Full;

        println!("metrics ({:?})", self.level);

        let page_cache_misses = metrics.load(Slot::PageCacheMisses);
        if full {
            let page_requests = metrics.load(Slot::PageRequests);
            println!("  page requests         {}", page_requests);
            if page_requests != 0 {
                println!(
                    "  page cache misses     {} - {:.2}% of page requests",
                    page_cache_misses,
                    (page_cache_misses as f64 / page_requests as f64) * 100.0
                );
            }
        } else {
            println!("  page cache misses     {}", page_cache_misses);
        }

        let leaf_cache_misses = metrics.load(Slot::LeafCacheMisses);
        if full {
            let leaf_cache_requests = metrics.load(Slot::LeafCacheRequests);
            println!("  leaf cache requests   {}", leaf_cache_requests);
            if leaf_cache_requests != 0 {
                println!(
                    "  leaf cache misses     {} - {:.2}% of leaf cache requests",
                    leaf_cache_misses,
                    (leaf_cache_misses as f64 / leaf_cache_requests as f64) * 100.0
                );
            }
        } else {
            println!("  leaf cache misses     {}", leaf_cache_misses);
        }

        println!("  ht page reads         {}", metrics.load(Slot::HtReads));
        println!("  ln page reads         {}", metrics.load(Slot::LnReads));

        if let Some(mean) = metrics.mean(Metric::PageFetchTime.timer_slots()) {
            println!("  page fetch mean       {}", pretty_display_ns(mean));
        }

        if let Some(mean) = metrics.mean(Metric::ValueFetchTime.timer_slots()) {
            println!("  value fetch mean      {}", pretty_display_ns(mean));
        }
    }

    /// The active metrics.
    ///
    /// Panics if the given metric is not collected at the configured level.
    fn active(&self, metric: Metric) -> &ActiveMetrics {
        self.collecting(&metric).expect(METRIC_NOT_COLLECTED)
    }

    /// Counter of total page requests.
    /// Collected at [`MetricsLevel::Full`]. Panics if not collected at the configured level.
    pub fn get_page_requests(&self) -> u64 {
        self.active(Metric::PageRequests).load(Slot::PageRequests)
    }

    /// Counter of page requests cache misses over all page requests.
    /// Collected at [`MetricsLevel::Io`]. Panics if not collected at the configured level.
    pub fn get_page_cache_misses(&self) -> u64 {
        self.active(Metric::PageCacheMisses)
            .load(Slot::PageCacheMisses)
    }

    /// Counter of beatree leaf cache lookups.
    /// Collected at [`MetricsLevel::Full`]. Panics if not collected at the configured level.
    pub fn get_leaf_cache_requests(&self) -> u64 {
        self.active(Metric::LeafCacheRequests)
            .load(Slot::LeafCacheRequests)
    }

    /// Counter of beatree leaf cache lookups which missed and had to read the `ln` file.
    /// Collected at [`MetricsLevel::Io`]. Panics if not collected at the configured level.
    pub fn get_leaf_cache_misses(&self) -> u64 {
        self.active(Metric::LeafCacheMisses)
            .load(Slot::LeafCacheMisses)
    }

    /// Counter of page reads issued to the hash-table (`ht`) file, which stores merkle pages.
    /// Collected at [`MetricsLevel::Io`]. Panics if not collected at the configured level.
    pub fn get_ht_reads(&self) -> u64 {
        self.active(Metric::HtReads).load(Slot::HtReads)
    }

    /// Counter of page reads issued to the beatree leaf (`ln`) file, which stores leaves and
    /// overflow value pages.
    /// Collected at [`MetricsLevel::Io`]. Panics if not collected at the configured level.
    pub fn get_ln_reads(&self) -> u64 {
        self.active(Metric::LnReads).load(Slot::LnReads)
    }

    /// Average page fetch time: the time to load a merkle page from the hash-table after a page
    /// cache miss, including all probes. See [`Metric::PageFetchTime`].
    /// Returns None if there were no requests.
    /// Collected at [`MetricsLevel::Io`]. Panics if not collected at the configured level.
    pub fn get_page_fetch_time(&self) -> Option<u64> {
        self.active(Metric::PageFetchTime)
            .mean(Metric::PageFetchTime.timer_slots())
    }

    /// Average value fetch time during reads.
    /// Returns None if there were no requests.
    /// Collected at [`MetricsLevel::Full`]. Panics if not collected at the configured level.
    pub fn get_value_fetch_time(&self) -> Option<u64> {
        self.active(Metric::ValueFetchTime)
            .mean(Metric::ValueFetchTime.timer_slots())
    }
}

fn pretty_display_ns(ns: u64) -> String {
    // preserve 3 sig figs at minimum.
    let (val, unit) = if ns > 100 * 1_000_000_000 {
        (ns / 1_000_000_000, "s")
    } else if ns > 100 * 1_000_000 {
        (ns / 1_000_000, "ms")
    } else if ns > 100 * 1_000 {
        (ns / 1_000, "us")
    } else {
        (ns, "ns")
    };

    format!("{val} {unit}")
}

#[cfg(test)]
mod tests {
    use super::{Metric, Metrics, MetricsLevel, STRIPES};
    use std::time::Duration;

    #[test]
    fn stripes_sum_across_threads() {
        let metrics = Metrics::new(MetricsLevel::Full);
        let threads = STRIPES + 3;
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| {
                    for _ in 0..1000 {
                        metrics.count(Metric::LeafCacheRequests);
                    }
                    metrics.count(Metric::LnReads);
                    metrics.record_duration(Metric::PageFetchTime, Duration::from_nanos(10));
                    metrics.record_duration(Metric::PageFetchTime, Duration::from_nanos(30));
                });
            }
        });
        assert_eq!(metrics.get_leaf_cache_requests(), 1000 * threads as u64);
        assert_eq!(metrics.get_ln_reads(), threads as u64);
        assert_eq!(metrics.get_leaf_cache_misses(), 0);
        assert_eq!(metrics.get_page_fetch_time(), Some(20));
        assert_eq!(metrics.get_value_fetch_time(), None);
    }

    #[test]
    fn io_level_collects_only_io_metrics() {
        let metrics = Metrics::new(MetricsLevel::Io);
        assert_eq!(metrics.metrics_level(), MetricsLevel::Io);

        metrics.count(Metric::PageRequests);
        metrics.count(Metric::PageCacheMisses);
        metrics.count(Metric::LeafCacheRequests);
        metrics.count(Metric::LeafCacheMisses);
        metrics.count(Metric::HtReads);
        metrics.count(Metric::LnReads);
        metrics.record_duration(Metric::PageFetchTime, Duration::from_nanos(10));
        assert!(metrics.record(Metric::ValueFetchTime).is_none());

        assert_eq!(metrics.get_page_cache_misses(), 1);
        assert_eq!(metrics.get_leaf_cache_misses(), 1);
        assert_eq!(metrics.get_ht_reads(), 1);
        assert_eq!(metrics.get_ln_reads(), 1);
        assert_eq!(metrics.get_page_fetch_time(), Some(10));

        // Full-level metrics are neither collected nor readable.
        assert!(std::panic::catch_unwind(|| metrics.get_page_requests()).is_err());
        assert!(std::panic::catch_unwind(|| metrics.get_leaf_cache_requests()).is_err());
        assert!(std::panic::catch_unwind(|| metrics.get_value_fetch_time()).is_err());
    }

    #[test]
    fn off_level_collects_nothing() {
        let metrics = Metrics::new(MetricsLevel::Off);
        assert_eq!(metrics.metrics_level(), MetricsLevel::Off);
        metrics.count(Metric::HtReads);
        assert!(metrics.record(Metric::ValueFetchTime).is_none());
        assert!(std::panic::catch_unwind(|| metrics.get_ht_reads()).is_err());
    }
}
