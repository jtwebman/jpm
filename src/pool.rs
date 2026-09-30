//! A work queue over scoped threads: jobs may add more jobs, and `run` returns once every job,
//! including those added, is done. Everything blocking (network, disk) runs on one of these.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, PoisonError};

pub struct Queue<T> {
    state: Mutex<(VecDeque<T>, usize)>,
    ready: Condvar,
    grow: Arc<Grow>,
}

/// What the thread that called `run` waits on to start workers: how many more waits on the
/// network have asked for one, and whether every job is done.
#[derive(Default)]
struct Grow {
    state: Mutex<(usize, bool)>,
    changed: Condvar,
}

impl Grow {
    fn update(&self, f: impl FnOnce(&mut (usize, bool))) {
        f(&mut self.state.lock().unwrap_or_else(PoisonError::into_inner));
        self.changed.notify_one();
    }

    /// How many more workers to start, at most `left`, once one is asked for; `None` once the
    /// work is done.
    fn more(&self, left: usize) -> Option<usize> {
        let mut g = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        while g.0 == 0 && !g.1 {
            g = self.changed.wait(g).unwrap_or_else(PoisonError::into_inner);
        }
        (!g.1).then(|| std::mem::take(&mut g.0).min(left))
    }
}

thread_local! {
    /// The pool this thread is a worker of.
    static POOL: RefCell<Option<Arc<Grow>>> = const { RefCell::new(None) };
}

/// Around a wait on the network or on another process. A pool starts with one worker per core,
/// enough for work that reads the disk; each such wait lets the pool this thread works for start
/// one more, up to its limit, so the waits overlap.
pub fn blocking<R>(f: impl FnOnce() -> R) -> R {
    ask();
    f()
}

/// This thread is a worker of the pool `grow` belongs to.
fn join(grow: &Arc<Grow>) {
    POOL.with(|p| *p.borrow_mut() = Some(grow.clone()));
}

fn ask() {
    POOL.with(|p| {
        if let Some(grow) = &*p.borrow() {
            grow.update(|s| s.0 += 1);
        }
    });
}

impl<T> Queue<T> {
    pub fn push(&self, job: T) {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.0.push_back(job);
        s.1 += 1;
        self.ready.notify_one();
    }
}

/// Marks a job done even when it panics, so the other threads never wait on it forever.
struct Done<'a, T>(&'a Queue<T>);

impl<T> Drop for Done<'_, T> {
    fn drop(&mut self) {
        let mut s = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.1 -= 1;
        if s.1 == 0 {
            self.0.ready.notify_all();
            self.0.grow.update(|g| g.1 = true);
        }
    }
}

/// Run `work` over `seed` and whatever it pushes, on at most `threads` threads: one per core at
/// first, and more as `blocking` asks for them.
pub fn run<T: Send>(threads: usize, seed: impl IntoIterator<Item = T>, work: impl Fn(T, &Queue<T>) + Sync) {
    let jobs: VecDeque<T> = seed.into_iter().collect();
    if jobs.is_empty() {
        return;
    }
    let pending = jobs.len();
    let queue = Queue { state: Mutex::new((jobs, pending)), ready: Condvar::new(), grow: Arc::default() };
    let threads = threads.clamp(1, 256);
    let started = threads.min(disk_threads());
    std::thread::scope(|scope| {
        let worker = || {
            join(&queue.grow);
            loop {
                let job = {
                    let mut s = queue.state.lock().unwrap_or_else(PoisonError::into_inner);
                    loop {
                        if let Some(job) = s.0.pop_front() {
                            break Some(job);
                        }
                        if s.1 == 0 {
                            break None;
                        }
                        s = queue.ready.wait(s).unwrap_or_else(PoisonError::into_inner);
                    }
                };
                let Some(job) = job else { return };
                let _done = Done(&queue);
                work(job, &queue);
            }
        };
        // One worker per core, then each one `blocking` asks for, until the work is done.
        let (mut more, mut left) = (started, threads - started);
        loop {
            for _ in 0..more {
                scope.spawn(worker);
            }
            let Some(n) = queue.grow.more(left) else { return };
            (more, left) = (n, left - n);
        }
    });
}

/// `f` over every item on up to `threads` threads, results in the items' order.
pub fn map<T: Send, R: Send>(threads: usize, items: Vec<T>, f: impl Fn(T) -> R + Sync) -> Vec<R> {
    let out: Vec<Mutex<Option<R>>> = (0..items.len()).map(|_| Mutex::new(None)).collect();
    run(threads, items.into_iter().enumerate(), |(i, item), _| {
        let r = f(item);
        *out[i].lock().unwrap_or_else(PoisonError::into_inner) = Some(r);
    });
    out.into_iter().filter_map(|m| m.into_inner().unwrap_or_else(PoisonError::into_inner)).collect()
}

/// Threads for network-bound work: `JPM_CONCURRENCY`, else 32.
pub fn network_threads() -> usize {
    std::env::var("JPM_CONCURRENCY").ok().and_then(|v| v.parse().ok()).filter(|n| *n > 0).unwrap_or(32)
}

/// Threads for disk-bound work: the cores this process may use, asked once (on Linux the answer
/// reads the cgroup's files each time).
pub fn disk_threads() -> usize {
    static CORES: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CORES.get_or_init(|| std::thread::available_parallelism().map_or(4, usize::from).max(2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn runs_jobs_that_add_jobs() {
        let count = AtomicUsize::new(0);
        run(4, [10u32], |n, q| {
            count.fetch_add(1, Ordering::Relaxed);
            if n > 0 {
                q.push(n - 1);
                q.push(0);
            }
        });
        assert_eq!(count.load(Ordering::Relaxed), 21);
    }

    /// The threads `run` used for `jobs` jobs of `job`, on at most `threads`; every job done.
    fn threads_used(threads: usize, jobs: usize, job: impl Fn() + Sync) -> usize {
        let seen = Mutex::new(std::collections::HashSet::new());
        let count = AtomicUsize::new(0);
        run(threads, 0..jobs, |_, _| {
            seen.lock().unwrap().insert(std::thread::current().id());
            job();
            count.fetch_add(1, Ordering::Relaxed);
        });
        assert_eq!(count.load(Ordering::Relaxed), jobs);
        seen.into_inner().unwrap().len()
    }

    #[test]
    fn grows_only_while_waiting_on_the_network() {
        let wait = || std::thread::sleep(std::time::Duration::from_millis(5));
        let cores = disk_threads();
        // Work that never waits on the network keeps one thread per core.
        assert!(threads_used(32, 200, wait) <= cores);
        // Waits on the network add threads, up to the limit and no further.
        let used = threads_used(32, 200, || blocking(wait));
        assert!(used > cores && used <= 32, "{used} threads");
        assert!(threads_used(cores + 2, 200, || blocking(wait)) <= cores + 2);
        assert_eq!(threads_used(1, 20, || blocking(wait)), 1);
    }

    #[test]
    fn grows_when_every_worker_waits() {
        // Each job waits for more jobs than there are cores to be waiting at once: that finishes
        // only if waiting workers let others start.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let n = disk_threads() + 2;
            let all = std::sync::Barrier::new(n);
            tx.send(threads_used(n, n, || _ = blocking(|| all.wait()))).unwrap();
        });
        let used = rx.recv_timeout(std::time::Duration::from_secs(10)).expect("every worker waits forever");
        assert_eq!(used, disk_threads() + 2);
    }

    #[test]
    fn maps_in_order() {
        assert_eq!(map(3, (0..50).collect(), |x| x * 2), (0..50).map(|x| x * 2).collect::<Vec<_>>());
        assert!(map(3, Vec::<u8>::new(), |x| x).is_empty());
    }
}
