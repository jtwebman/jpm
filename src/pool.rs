//! A work queue over scoped threads: jobs may add more jobs, and `run` returns once every job,
//! including those added, is done. Everything blocking (network, disk) runs on one of these.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, PoisonError};

pub struct Queue<T> {
    state: Mutex<(VecDeque<T>, usize)>,
    ready: Condvar,
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
        }
    }
}

/// Run `work` over `seed` and whatever it pushes, on at most `threads` threads.
pub fn run<T: Send>(threads: usize, seed: impl IntoIterator<Item = T>, work: impl Fn(T, &Queue<T>) + Sync) {
    let jobs: VecDeque<T> = seed.into_iter().collect();
    if jobs.is_empty() {
        return;
    }
    let pending = jobs.len();
    let queue = Queue { state: Mutex::new((jobs, pending)), ready: Condvar::new() };
    let threads = threads.clamp(1, 256);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
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
            });
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

/// Threads for disk-bound work: the cores this process may use.
pub fn disk_threads() -> usize {
    std::thread::available_parallelism().map_or(4, usize::from).max(2)
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

    #[test]
    fn maps_in_order() {
        assert_eq!(map(3, (0..50).collect(), |x| x * 2), (0..50).map(|x| x * 2).collect::<Vec<_>>());
        assert!(map(3, Vec::<u8>::new(), |x| x).is_empty());
    }
}
