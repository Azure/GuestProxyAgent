// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/// Converts a `stat` `st_dev` (userspace encoding: glibc `makedev`) to the kernel-internal
/// `dev_t` encoding (`MKDEV`: major << 20 | minor) that `super_block->s_dev` holds and that
/// the eBPF program reports in `Claims::processExecutableDevice`.
pub(crate) fn kernel_dev_from_st_dev(st_dev: u64) -> u64 {
    let major = u64::from(libc::major(st_dev));
    let minor = u64::from(libc::minor(st_dev));
    (major << 20) | minor
}

/// Returns the `mnt_id` line value from a `/proc/<pid>/fdinfo/<fd>` dump.
fn mount_id_from_fdinfo(fdinfo: &str) -> Option<&str> {
    fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .map(str::trim)
}

/// Returns the superblock `dev_t` (kernel encoding) of the mount with `mount_id`.
/// Equals the eBPF `s_dev` on Ubuntu 6.8 Btrfs but not on SLES 15 SP4 Btrfs; see `Identity::is_match`.
fn sb_dev_from_mountinfo(mountinfo: &str, mount_id: &str) -> Option<u64> {
    let line = mountinfo
        .lines()
        .find(|line| line.split_whitespace().next() == Some(mount_id))?;
    let (major, minor) = line.split_whitespace().nth(2)?.split_once(':')?;
    Some((major.parse::<u64>().ok()? << 20) | minor.parse::<u64>().ok()?)
}

/// Superblock device of the filesystem holding `path`, as the eBPF hook reports it.
pub(crate) fn sb_dev_of_path(path: &str) -> Option<u64> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    // O_PATH never blocks on FIFOs or devices.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).ok()?;
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    sb_dev_from_mountinfo(&mountinfo, mount_id_from_fdinfo(&fdinfo)?)
}

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
    #[test]
    fn kernel_dev_from_st_dev_matches_kernel_encoding() {
        // /dev/sda1 (8,1): stat st_dev is 0x801, kernel s_dev is 0x800001.
        assert_eq!(super::kernel_dev_from_st_dev(0x801), 0x80_0001);
        // Minor numbers above 255 are split across the userspace encoding.
        let st_dev = libc::makedev(259, 0x1234);
        assert_eq!(
            super::kernel_dev_from_st_dev(st_dev),
            (259u64 << 20) | 0x1234
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn sb_dev_lookup_uses_mountinfo_not_stat_dev() {
        let mountinfo = "26 1 0:49 / /mnt/btrfs-test rw,relatime shared:1 - btrfs /dev/loop0 rw,space_cache=v2,subvolid=5,subvol=/\n\
            27 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n";
        assert_eq!(super::sb_dev_from_mountinfo(mountinfo, "26"), Some(49));
        assert_eq!(
            super::sb_dev_from_mountinfo(mountinfo, "27"),
            Some((8u64 << 20) | 1)
        );
        assert_eq!(super::sb_dev_from_mountinfo(mountinfo, "2"), None);
        assert_eq!(
            super::mount_id_from_fdinfo("pos:\t0\nflags:\t010000000\nmnt_id:\t26\n"),
            Some("26")
        );
        assert!(super::sb_dev_of_path("/proc/self/exe").is_some());
        assert!(super::sb_dev_of_path("/nonexistent/path").is_none());
    }
}
