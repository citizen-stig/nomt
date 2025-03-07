use std::sync::{Arc, Mutex};

use rand::{distributions::WeightedIndex, Rng, RngCore};

use super::{
    resource::ResourceAllocator,
    swarm::{self, SwarmFeatures},
    ResourceExhaustion,
};

/// Percentage of the assigned space to the workload that will be
/// used by the hash table stored on disk.
const HASH_TABLE_SIZE_RATIO_DISK: f64 = 0.8;

/// Percentage of the assigned space to the workload that will be
/// used by the hash table stored in memory.
///
/// This is smaller than `HASH_TABLE_SIZE_RATIO_DISK` becaues it accounts
/// also for all the other things that need to be stored in memory,
/// not only the workload directory.
const HASH_TABLE_SIZE_RATIO_MEM: f64 = 0.5;

/// Maximum size of a single commit, combining reads and updates.
const MAX_COMMIT_SIZE: usize = 200_000;

/// Maximum number of times a workload is repeated
const MAX_ITERATIONS: usize = 10_000;

/// Maximum number of commit workers supported by nomt.
const MAX_COMMIT_CONCURRENCY: usize = 64;

/// Maximum number of io workers supported by nomt.
const MAX_IO_WORKERS: usize = 32;

/// Maximum amount of MiB that an in memory cache can occupy.
///
/// It refers to leaf and page cache.
const MAX_IN_MEMORY_CACHE_SIZE: usize = 512;

/// Maximum supported number of page cache upper levels.
const MAX_PAGE_CACHE_UPPER_LEVELS: usize = 3;

#[derive(Debug)]
pub struct WorkloadConfiguration {
    /// The seed for bitbox generated for this workload.
    pub bitbox_seed: [u8; 16],
    /// How many iterations the workload should perform.
    pub iterations: usize,
    /// The number of commit workers.
    pub commit_concurrency: usize,
    /// The number of io_uring instances.
    pub io_workers: usize,
    /// The number of pages within the ht.
    pub hashtable_buckets: u32,
    /// Whether merkle page fetches should be warmed up while sessions are ongoing.
    pub warm_up: bool,
    /// Whether to preallocate the hashtable file.
    pub preallocate_ht: bool,
    /// The maximum size of the page cache.
    pub page_cache_size: usize,
    /// The maximum size of the leaf cache.
    pub leaf_cache_size: usize,
    /// Whether to prepopulate the upper layers of the page cache on startup.
    pub prepopulate_page_cache: bool,
    /// Number of upper layers contained in the cache.
    pub page_cache_upper_levels: usize,
    /// The average size of a commit, combining reads and updates.
    pub avg_commit_size: usize,
    /// Percentage of `avg_commit_size` that will be designated for reads,
    /// the rest will be used by the changeset.
    pub reads: f64,
    /// The number of concurrent readers.
    pub read_concurrency: usize,
    /// The probability of reading an already existing key.
    pub read_existing_key: f64,
    /// The weight of generating an update operation when constructing the changeset.
    pub update_key: f64,
    /// The weight of generating a deletion operation when constructing the changeset.
    pub delete_key: f64,
    /// The weight of generating an insertion operation when constructing the changeset.
    pub new_key: f64,
    /// When generating a value, the probability of generating a value that will spill into the
    /// overflow pages.
    pub overflow: f64,
    /// Whether to ensure the correct application of the changeset after every commit.
    pub ensure_changeset: bool,
    /// Whether to randomly sample the state after every crash or rollback.
    pub sample_snapshot: bool,
    /// Distribution used when generating a new key to decide how many bytes needs to be shared
    /// with an already existing key.
    pub new_key_distribution: WeightedIndex<usize>,
    /// When executing a commit this is the probability of causing it to crash.
    pub commit_crash: f64,
    /// When executing a workload iteration ,this is the probability of executing a rollback.
    pub rollback: f64,
    /// The max number of commits involved in a rollback.
    pub max_rollback_commits: u32,
    /// When executing a rollback this is the probability of causing it to crash.
    pub rollback_crash: f64,
    /// Whether trickfs will be used or not.
    ///
    /// If false, enospc_on/off and latency_on/off will all be 0.
    pub trickfs: bool,
    /// The probability of turning on the `ENOSPC` error.
    pub enospc_on: f64,
    /// The probability of turning off the `ENOSPC` error.
    pub enospc_off: f64,
    /// The probability of turning on the latency injector.
    pub latency_on: f64,
    /// The probability of turning off the latency injector.
    pub latency_off: f64,
    // Whether to ensure the correctness of the entire state after every crash or rollback.
    //
    // This is only used when repeating a failed workload.
    ensure_snapshot: bool,
}

impl WorkloadConfiguration {
    pub fn new(
        rng: &mut rand_pcg::Pcg64,
        resource_alloc: Arc<Mutex<ResourceAllocator>>,
        workload_id: u64,
    ) -> Result<Self, ResourceExhaustion> {
        let swarm_features = swarm::new_features_set(rng);

        let trickfs = swarm_features
            .iter()
            .find(|feature| {
                matches!(
                    feature,
                    SwarmFeatures::TrickfsENOSPC | SwarmFeatures::TrickfsLatencyInjection
                )
            })
            .is_some();

        let avail_bytes = {
            let mut allocator = resource_alloc.lock().unwrap();
            if trickfs {
                allocator.alloc_memory(workload_id)?;
                allocator.assigned_memory(workload_id)
            } else {
                allocator.alloc(workload_id)?;
                allocator.assigned_disk(workload_id)
            }
        };

        let mut bitbox_seed = [0u8; 16];
        rng.fill_bytes(&mut bitbox_seed);

        let hashtable_size = if trickfs {
            (avail_bytes as f64 * HASH_TABLE_SIZE_RATIO_MEM) as u64
        } else {
            (avail_bytes as f64 * HASH_TABLE_SIZE_RATIO_DISK) as u64
        };
        const PAGE_SIZE: u64 = 4096;
        let hashtable_buckets = (hashtable_size / PAGE_SIZE) as u32;

        // When generating a new key to be inserted in the database,
        // this distribution will generate the key.
        // There is a 25% chance that the key is completely random,
        // half of the 25% chance that the first byte will be shared with an existing key,
        // one third of the 25% chance that two bytes will be shared with an existing key,
        // and so on.
        //
        // There are:
        // + 25% probability of having a key with 0 shared bytes.
        // + 48% probability of having a key with 1 to 9 shared bytes.
        // + 27% probability of having a key with more than 10 shared bytes.
        //
        // UNWRAP: provided iterator is not empty, no item is lower than zero
        // and the total sum is greater than one.
        let new_key_distribution = WeightedIndex::new((1usize..33).map(|x| (32 * 32) / x)).unwrap();

        let mut config = Self {
            read_existing_key: 0.0,
            new_key: 0.0,
            delete_key: 0.0,
            update_key: 0.0,
            overflow: 0.0,
            rollback: 0.0,
            commit_crash: 0.0,
            rollback_crash: 0.0,
            trickfs,
            enospc_on: 0.0,
            enospc_off: 0.0,
            latency_on: 0.0,
            latency_off: 0.0,
            ensure_changeset: false,
            ensure_snapshot: false,
            sample_snapshot: false,
            max_rollback_commits: 0,
            reads: 0.0,
            read_concurrency: 1,
            warm_up: false,
            preallocate_ht: false,
            prepopulate_page_cache: false,
            new_key_distribution,
            bitbox_seed,
            iterations: rng.gen_range(1..=MAX_ITERATIONS),
            avg_commit_size: rng.gen_range(1..=(MAX_COMMIT_SIZE / 2)),
            commit_concurrency: rng.gen_range(1..=MAX_COMMIT_CONCURRENCY),
            io_workers: rng.gen_range(1..=MAX_IO_WORKERS),
            page_cache_size: rng.gen_range(1..=MAX_IN_MEMORY_CACHE_SIZE),
            leaf_cache_size: rng.gen_range(1..=MAX_IN_MEMORY_CACHE_SIZE),
            page_cache_upper_levels: rng.gen_range(0..=MAX_PAGE_CACHE_UPPER_LEVELS),
            hashtable_buckets,
        };

        for swarm_feature in swarm_features {
            config.apply_swarm_feature(rng, swarm_feature);
        }

        Ok(config)
    }

    pub fn is_rollback_enable(&self) -> bool {
        self.rollback > 0.0
    }

    pub fn no_new_keys(&self) -> bool {
        self.new_key == 0.0
    }

    pub fn enable_ensure_snapshot(&mut self) {
        self.ensure_snapshot = true;
    }

    pub fn should_ensure_snapshot(&mut self) -> bool {
        self.ensure_snapshot
    }

    pub fn apply_swarm_feature(&mut self, rng: &mut rand_pcg::Pcg64, feature: SwarmFeatures) {
        match feature {
            SwarmFeatures::TrickfsENOSPC => {
                self.enospc_on = rng.gen_range(0.01..=1.00);
                self.enospc_off = rng.gen_range(0.01..=1.00);
            }
            SwarmFeatures::TrickfsLatencyInjection => {
                self.latency_on = rng.gen_range(0.01..=1.00);
                self.latency_off = rng.gen_range(0.01..=1.00);
            }
            SwarmFeatures::EnsureChangeset => self.ensure_changeset = true,
            SwarmFeatures::SampleSnapshot => self.sample_snapshot = true,
            SwarmFeatures::WarmUp => self.warm_up = true,
            SwarmFeatures::PreallocateHt => self.preallocate_ht = true,
            SwarmFeatures::Read => {
                self.reads = rng.gen_range(0.01..1.00);
                self.read_concurrency = rng.gen_range(1..=64);
                self.read_existing_key = rng.gen_range(0.01..1.00);
            }
            SwarmFeatures::Rollback => {
                self.rollback = rng.gen_range(0.01..1.00);
                // During scheduling of rollbacks the lower bound is 1
                // thus max must be at least 2 to avoid creating an empty range.
                self.max_rollback_commits = rng.gen_range(2..100);
            }
            SwarmFeatures::RollbackCrash => self.rollback_crash = rng.gen_range(0.01..1.00),
            SwarmFeatures::CommitCrash => self.commit_crash = rng.gen_range(0.01..1.00),
            SwarmFeatures::PrepopulatePageCache => self.prepopulate_page_cache = true,
            SwarmFeatures::NewKeys => self.new_key = rng.gen_range(0.01..=1.00),
            SwarmFeatures::DeleteKeys => self.delete_key = rng.gen_range(0.01..=1.00),
            SwarmFeatures::UpdateKeys => self.update_key = rng.gen_range(0.01..=1.00),
            SwarmFeatures::OverflowValues => self.overflow = rng.gen_range(0.01..=1.00),
        }
    }
}
