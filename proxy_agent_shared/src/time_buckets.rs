// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

/// Trait for items that have a count field.
pub trait Countable {
    fn set_count(&mut self, count: u64);
}

/// A generic container that buckets counts over time.
/// This helps in aging out old items.
pub struct TimeBucketedItem<T> {
    item: T,                              // base info (count will be computed)
    buckets: VecDeque<(SystemTime, u64)>, // (bucket_start, count_in_bucket)
    bucket_duration: Duration,
    max_age: Duration,
}

impl<T> TimeBucketedItem<T> {
    pub fn new(item: T, bucket_duration: Duration, max_age: Duration) -> Self {
        let now = SystemTime::now();
        let mut buckets = VecDeque::new();
        buckets.push_back((now, 1));
        Self {
            item,
            buckets,
            bucket_duration,
            max_age,
        }
    }

    /// Adds one to the count.
    /// Returns true if a new bucket was created.
    pub fn add_one(&mut self) -> bool {
        let now = SystemTime::now();
        self.prune_old_buckets(now);

        // Check if we can add to current bucket
        if let Some((bucket_time, count)) = self.buckets.back_mut() {
            if now.duration_since(*bucket_time).unwrap_or_default() < self.bucket_duration {
                *count += 1;
                return false;
            }
        }
        // Create new bucket
        self.buckets.push_back((now, 1));
        true
    }

    /// Prunes buckets older than MAX_AGE_SECS.
    fn prune_old_buckets(&mut self, now: SystemTime) {
        let max_age = self.max_age;
        while let Some((bucket_time, _)) = self.buckets.front() {
            if now.duration_since(*bucket_time).unwrap_or(max_age) >= max_age {
                self.buckets.pop_front();
            } else {
                break;
            }
        }
    }

    /// Gets the total count across all buckets.
    fn get_count(&mut self) -> u64 {
        self.prune_old_buckets(SystemTime::now());
        self.buckets.iter().map(|(_, c)| c).sum()
    }

    /// Checks if there are no buckets left.
    pub fn is_empty(&mut self) -> bool {
        self.prune_old_buckets(SystemTime::now());
        self.buckets.is_empty()
    }
}

impl<T: Clone + Countable> TimeBucketedItem<T> {
    /// Converts to the item type with updated count.
    pub fn to_item(&mut self) -> T {
        let mut result = self.item.clone();
        result.set_count(self.get_count());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[derive(Clone, Debug, PartialEq)]
    struct TestItem {
        name: String,
        count: u64,
    }

    impl Countable for TestItem {
        fn set_count(&mut self, count: u64) {
            self.count = count;
        }
    }

    #[test]
    fn test_new_creates_single_bucket() {
        let item = TestItem {
            name: "test".to_string(),
            count: 0,
        };
        let bucket_duration = Duration::from_secs(60);
        let max_age = Duration::from_secs(300);

        // test_new_creates_single_bucket_with_count_one
        let mut bucketed = TimeBucketedItem::new(item, bucket_duration, max_age);
        assert_eq!(bucketed.get_count(), 1);
        assert!(!bucketed.is_empty());

        // test_add_one_increments_count_in_same_bucket()
        let new_bucket = bucketed.add_one();

        assert!(!new_bucket); // Should not create new bucket
        assert_eq!(bucketed.get_count(), 2);
    }

    #[test]
    fn test_add_one_creates_new_bucket_after_duration() {
        let item = TestItem {
            name: "test".to_string(),
            count: 0,
        };
        // Use very short bucket duration for testing
        let bucket_duration = Duration::from_millis(10);
        let max_age = Duration::from_secs(300);

        let mut bucketed = TimeBucketedItem::new(item, bucket_duration, max_age);

        // Wait for bucket duration to pass
        sleep(Duration::from_millis(15));

        let new_bucket = bucketed.add_one();

        assert!(new_bucket); // Should create new bucket
        assert_eq!(bucketed.get_count(), 2); // Both buckets should count
    }

    #[test]
    fn test_prune_old_buckets_removes_expired_buckets() {
        let item = TestItem {
            name: "test".to_string(),
            count: 0,
        };
        // Use very short durations for testing
        let bucket_duration = Duration::from_millis(5);
        let max_age = Duration::from_millis(20);

        let mut bucketed = TimeBucketedItem::new(item, bucket_duration, max_age);

        // Add counts over time to create multiple buckets
        sleep(Duration::from_millis(10));
        bucketed.add_one();

        // Wait for max_age to pass for the first bucket
        sleep(Duration::from_millis(25));

        // This should prune the old bucket and create a new one
        bucketed.add_one();

        // The initial bucket should be pruned, only newer counts should remain
        let count = bucketed.get_count();
        assert!(count <= 2); // Should have pruned at least the first bucket
    }

    #[test]
    fn test_is_empty_after_all_buckets_expire() {
        let item = TestItem {
            name: "test".to_string(),
            count: 0,
        };
        // Use very short max_age for testing
        let bucket_duration = Duration::from_millis(5);
        let max_age = Duration::from_millis(10);

        let mut bucketed = TimeBucketedItem::new(item, bucket_duration, max_age);
        assert!(!bucketed.is_empty());

        // Wait for all buckets to expire
        sleep(Duration::from_millis(20));

        assert!(bucketed.is_empty());
    }

    #[test]
    fn test_to_item_returns_cloned_item_with_count() {
        let item = TestItem {
            name: "test".to_string(),
            count: 0,
        };
        let bucket_duration = Duration::from_secs(60);
        let max_age = Duration::from_secs(300);

        let mut bucketed = TimeBucketedItem::new(item, bucket_duration, max_age);
        bucketed.add_one();
        bucketed.add_one();

        assert_eq!(bucketed.get_count(), 3); // 1 from new + 2 from add_one
        let result = bucketed.to_item();

        assert_eq!(result.name, "test");
        assert_eq!(result.count, 3); // 1 from new + 2 from add_one
    }

    #[test]
    fn test_bucket_count_accumulates_across_buckets() {
        let item = TestItem {
            name: "test".to_string(),
            count: 0,
        };
        // Use short bucket duration to force new buckets
        let bucket_duration = Duration::from_millis(5);
        let max_age = Duration::from_secs(60);

        let mut bucketed = TimeBucketedItem::new(item, bucket_duration, max_age);

        // Add some counts
        bucketed.add_one();
        bucketed.add_one();

        // Wait to create new bucket
        sleep(Duration::from_millis(10));
        bucketed.add_one();
        bucketed.add_one();

        // Total should be 5 (1 from new + 4 from add_one)
        assert_eq!(bucketed.get_count(), 5);
    }
}
