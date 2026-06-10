// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Destination classification.
//!
//! Maps the host+port of an incoming request to one of GPA's known
//! endpoints (IMDS, WireServer, HostGAPlugin). Numeric host forms
//! (decimal, hex, octal, IPv4-mapped IPv6, etc.) all canonicalize to the
//! same variant — this is the defense against pentest C7.
//!
//! Hostnames that are not IP literals are *not* DNS-resolved here. DNS at
//! the matcher would be a confused-deputy surface; instead we surface the
//! host text in [`Destination::Unknown`] so rule authors can write
//! explicit allow rules keyed on host text if they need it.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hyper::Uri;

use crate::common::constants;

use super::CanonError;

/// Address family of an [`Destination::Unknown`] target. Kept narrow so
/// we don't accidentally treat numeric strings as hostnames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddrFamily {
    V4,
    V6,
    Name,
}

/// Canonical destination. Matching uses the typed enum only; the raw
/// `host_text` on `Unknown` is for audit, never for matching decisions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Destination {
    /// Instance Metadata Service: 169.254.169.254:80 in any encoding.
    Imds,
    /// Azure WireServer: 168.63.129.16:80.
    WireServer,
    /// Host GuestAgent Plugin: 168.63.129.16:32526.
    HostGaPlugin,
    /// Anything else. The matcher denies unknowns unless an explicit rule
    /// allows them.
    Unknown {
        family: AddrFamily,
        ip: Option<IpAddr>,
        port: u16,
        host_text: Option<String>,
    },
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Destination::Imds => f.write_str("imds"),
            Destination::WireServer => f.write_str("wireserver"),
            Destination::HostGaPlugin => f.write_str("hostga"),
            Destination::Unknown { .. } => f.write_str("unknown"),
        }
    }
}

/// Classify the destination of a request URI. See module docs.
pub fn classify(uri: &Uri) -> Result<Destination, CanonError> {
    // Reject userinfo (`user@host` smuggling).
    if uri
        .authority()
        .map(|a| a.as_str().contains('@'))
        .unwrap_or(false)
    {
        return Err(CanonError::UserinfoPresent);
    }

    let host = match uri.host() {
        Some(h) => h,
        // Origin-form requests (the common proxy case) have no authority.
        // We must still allow them to flow: the destination is decided by
        // the redirector at the socket layer, not by the URL.
        None => {
            return Ok(Destination::Unknown {
                family: AddrFamily::Name,
                ip: None,
                port: 0,
                host_text: None,
            });
        }
    };

    let port = uri.port_u16().unwrap_or(constants::IMDS_PORT);

    let ip = parse_host_as_ip(host)?;
    match ip {
        Some(IpAddr::V4(v4)) => Ok(known_v4(v4, port).unwrap_or(Destination::Unknown {
            family: AddrFamily::V4,
            ip: Some(IpAddr::V4(v4)),
            port,
            host_text: Some(host.to_string()),
        })),
        Some(IpAddr::V6(v6)) => {
            // IPv4-mapped IPv6 (::ffff:a.b.c.d) projects down to IPv4 so
            // it shares the same Destination as the dotted form.
            if let Some(v4) = v6.to_ipv4_mapped() {
                if let Some(known) = known_v4(v4, port) {
                    return Ok(known);
                }
                return Ok(Destination::Unknown {
                    family: AddrFamily::V4,
                    ip: Some(IpAddr::V4(v4)),
                    port,
                    host_text: Some(host.to_string()),
                });
            }
            Ok(Destination::Unknown {
                family: AddrFamily::V6,
                ip: Some(IpAddr::V6(v6)),
                port,
                host_text: Some(host.to_string()),
            })
        }
        None => Ok(Destination::Unknown {
            family: AddrFamily::Name,
            ip: None,
            port,
            host_text: Some(host.to_string()),
        }),
    }
}

fn known_v4(v4: Ipv4Addr, port: u16) -> Option<Destination> {
    let imds: Ipv4Addr = constants::IMDS_IP.parse().ok()?;
    let wire: Ipv4Addr = constants::WIRE_SERVER_IP.parse().ok()?;

    if v4 == imds && port == constants::IMDS_PORT {
        return Some(Destination::Imds);
    }
    if v4 == wire && port == constants::WIRE_SERVER_PORT {
        return Some(Destination::WireServer);
    }
    if v4 == wire && port == constants::GA_PLUGIN_PORT {
        return Some(Destination::HostGaPlugin);
    }
    None
}

/// Parse a host string into an `IpAddr` when it is an IP literal in any
/// historical numeric form. Returns `Ok(None)` for true hostnames (i.e.
/// not an IP), which the caller treats as `Destination::Unknown`.
///
/// Supports:
///   - dotted quad   `169.254.169.254`
///   - 32-bit decimal `2852039166`
///   - 32-bit hex     `0xa9fea9fe`
///   - octal-quad     `0251.0376.0251.0376`
///   - hex-quad       `0xa9.0xfe.0xa9.0xfe`
///   - mixed forms allowed per RFC 3493 / inet_aton tradition
///   - bracketed IPv6 `[::ffff:169.254.169.254]` (brackets handled by hyper)
fn parse_host_as_ip(host: &str) -> Result<Option<IpAddr>, CanonError> {
    // Tolerate both forms (hyper strips brackets in most versions but
    // not all). Strip surrounding `[]` if present before parsing IPv6.
    let host_unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(v6) = host_unbracketed.parse::<Ipv6Addr>() {
        return Ok(Some(IpAddr::V6(v6)));
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Ok(Some(IpAddr::V4(v4)));
    }

    // Trailing dot on hostname (`metadata.azure.internal.`) — strip then
    // re-classify. A bare `.` is not a host.
    let trimmed = host.trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(CanonError::BadHost);
    }

    if let Some(v4) = parse_inet_aton(trimmed)? {
        return Ok(Some(IpAddr::V4(v4)));
    }

    // Not an IP literal in any supported form. Distinguish "valid
    // hostname" from "garbage": at least one ASCII alphanumeric and no
    // forbidden characters.
    if trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && trimmed.chars().any(|c| c.is_ascii_alphanumeric())
    {
        Ok(None)
    } else {
        Err(CanonError::BadHost)
    }
}

/// `inet_aton`-style numeric IPv4 parser.
///
/// Implemented by hand (rather than calling out to libc) because
/// `inet_aton` behavior is platform-dependent: glibc accepts `0x` and
/// leading-zero octal; musl is stricter; Windows differs again. A
/// hand-rolled parser keeps Linux and Windows builds identical.
fn parse_inet_aton(input: &str) -> Result<Option<Ipv4Addr>, CanonError> {
    // Must look numeric. Reject early if it has any character outside the
    // numeric/separator set so we don't shadow a legitimate hostname.
    if input.is_empty() {
        return Err(CanonError::BadHost);
    }
    let looks_numeric = input
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == 'x' || c == 'X' || c == '.');
    if !looks_numeric {
        return Ok(None);
    }

    let parts: Vec<&str> = input.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return Err(CanonError::BadHost);
    }
    // Empty parts (e.g. trailing dot already stripped, double dot here)
    // are illegal.
    if parts.iter().any(|p| p.is_empty()) {
        return Err(CanonError::BadHost);
    }

    let nums: Vec<u32> = parts
        .iter()
        .map(|p| parse_numeric_octet(p))
        .collect::<Result<Vec<_>, _>>()?;

    let addr: u32 = match nums.len() {
        // single 32-bit number: maps directly
        1 => nums[0],
        // a.b => a in top 8 bits, b in low 24
        2 => {
            if nums[0] > 0xFF || nums[1] > 0x00FF_FFFF {
                return Err(CanonError::BadHost);
            }
            (nums[0] << 24) | nums[1]
        }
        // a.b.c => a,b top 16 bits, c low 16
        3 => {
            if nums[0] > 0xFF || nums[1] > 0xFF || nums[2] > 0xFFFF {
                return Err(CanonError::BadHost);
            }
            (nums[0] << 24) | (nums[1] << 16) | nums[2]
        }
        // a.b.c.d => standard dotted quad
        4 => {
            if nums.iter().any(|&n| n > 0xFF) {
                return Err(CanonError::BadHost);
            }
            (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
        }
        _ => return Err(CanonError::BadHost),
    };

    Ok(Some(Ipv4Addr::from(addr)))
}

fn parse_numeric_octet(s: &str) -> Result<u32, CanonError> {
    // 0x... => hex
    if let Some(rest) = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
    {
        if rest.is_empty() || rest.len() > 8 {
            return Err(CanonError::BadHost);
        }
        return u32::from_str_radix(rest, 16).map_err(|_| CanonError::BadHost);
    }
    // 0... (and not just "0") => octal
    if s.len() > 1 && s.starts_with('0') {
        return u32::from_str_radix(&s[1..], 8).map_err(|_| CanonError::BadHost);
    }
    // decimal
    s.parse::<u32>().map_err(|_| CanonError::BadHost)
}

#[cfg(test)]
mod destination_tests {
    use super::*;

    fn aton(s: &str) -> Result<Option<Ipv4Addr>, CanonError> {
        parse_inet_aton(s)
    }
    fn host(s: &str) -> Result<Option<IpAddr>, CanonError> {
        parse_host_as_ip(s)
    }
    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }
    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    // -----------------------------------------------------------------
    // parse_numeric_octet
    // -----------------------------------------------------------------

    #[test]
    fn numeric_octet_accepts_valid_forms() {
        // (input, expected). Covers decimal (incl. u32::MAX and lone
        // zero), hex with both prefix cases, and octal.
        let cases: &[(&str, u32)] = &[
            ("0", 0),
            ("169", 169),
            ("255", 255),
            ("4294967295", u32::MAX),
            ("0x0", 0),
            ("0xa9", 0xA9),
            ("0XA9", 0xA9),
            ("0xa9fea9fe", 0xA9FE_A9FE),
            ("0xFFFFFFFF", u32::MAX),
            ("0251", 0o251), // 169
            ("0376", 0o376), // 254
            ("00", 0),
        ];
        for (input, expected) in cases {
            assert_eq!(
                parse_numeric_octet(input).unwrap(),
                *expected,
                "input={input:?}"
            );
        }
    }

    #[test]
    fn numeric_octet_rejects_invalid_forms() {
        // All of these must be BadHost: decimal overflow, hex without
        // digits, hex too long for u32, non-hex digits in hex, non-octal
        // digits in an octal-prefixed string, and empty input.
        let bad: &[&str] = &[
            "4294967296",  // decimal overflow
            "0x",          // empty hex
            "0X",          // empty hex (upper prefix)
            "0x100000000", // hex too long for u32
            "0xZZ",        // bad hex digit
            "08",          // 8 is not octal
            "0129",        // 9 is not octal
            "",            // empty
        ];
        for input in bad {
            assert_eq!(
                parse_numeric_octet(input).unwrap_err(),
                CanonError::BadHost,
                "input={input:?}"
            );
        }
    }

    // -----------------------------------------------------------------
    // parse_inet_aton
    // -----------------------------------------------------------------

    #[test]
    fn inet_aton_accepts_all_numeric_forms() {
        let imds = Ipv4Addr::new(169, 254, 169, 254);
        // (input, expected). Covers dotted quad, single decimal, single
        // hex, octal/hex/mixed quads, and the 2-/3-part legacy forms.
        let two_part = {
            let v: u32 = (169u32 << 24) | 16_624_894;
            Ipv4Addr::from(v)
        };
        let cases: &[(&str, Ipv4Addr)] = &[
            ("169.254.169.254", imds),
            ("2852039166", imds),
            ("0xa9fea9fe", imds),
            ("0251.0376.0251.0376", imds),
            ("0xa9.0xfe.0xa9.0xfe", imds),
            ("169.0xfe.0251.254", imds),
            ("169.254.43518", imds),      // 3-part form
            ("169.16624894", two_part),   // 2-part form
        ];
        for (input, expected) in cases {
            assert_eq!(
                aton(input).unwrap(),
                Some(*expected),
                "input={input:?}"
            );
        }
    }

    #[test]
    fn inet_aton_rejects_malformed_inputs() {
        // Empty parts, too-many parts, octet overflow at each supported
        // arity, and the empty string itself.
        let bad: &[&str] = &[
            "",
            "1.2.3.4.5",   // too many parts
            "1..2.3",      // double dot
            ".1.2.3",      // leading dot
            "1.2.3.",      // trailing dot
            "300.1.1.1",   // 4-part octet > 0xFF
            "256.0.0.0",   // 4-part octet > 0xFF
            "256.1",       // 2-part top byte > 0xFF
            "1.16777216",  // 2-part low value > 0x00FF_FFFF
            "1.2.65536",   // 3-part last value > 0xFFFF
        ];
        for input in bad {
            assert_eq!(
                aton(input).unwrap_err(),
                CanonError::BadHost,
                "input={input:?}"
            );
        }
    }

    #[test]
    fn inet_aton_passes_through_non_numeric_hostnames() {
        // Hostnames must fall through with Ok(None), not error — the
        // caller decides whether to allow them.
        for input in ["metadata", "metadata.azure.internal", "host-with-dash"] {
            assert_eq!(aton(input).unwrap(), None, "input={input:?}");
        }
    }

    // -----------------------------------------------------------------
    // parse_host_as_ip
    // -----------------------------------------------------------------

    #[test]
    fn host_parses_all_ip_literal_forms() {
        // (input, expected IpAddr). Covers IPv4 dotted, IPv4 numeric
        // (falls through to inet_aton), IPv6 plain, IPv6 bracketed
        // (tolerance for hyper versions that don't strip brackets), and
        // IPv4-mapped IPv6.
        let v6_mapped: Ipv6Addr = "::ffff:169.254.169.254".parse().unwrap();
        let cases: &[(&str, IpAddr)] = &[
            ("127.0.0.1", IpAddr::V4(Ipv4Addr::LOCALHOST)),
            (
                "2852039166",
                IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            ),
            ("::1", IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ("[::1]", IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ("::ffff:169.254.169.254", IpAddr::V6(v6_mapped)),
        ];
        for (input, expected) in cases {
            assert_eq!(
                host(input).unwrap(),
                Some(*expected),
                "input={input:?}"
            );
        }
    }

    #[test]
    fn host_returns_none_for_valid_hostnames() {
        // Hostnames (including the RFC 1034 trailing-dot form) must not
        // be silently treated as IPs.
        for input in [
            "metadata.azure.internal",
            "metadata.azure.internal.",
            "foo",
            "a-b-c.example",
        ] {
            assert_eq!(host(input).unwrap(), None, "input={input:?}");
        }
    }

    #[test]
    fn host_rejects_garbage() {
        // Empty, bare dot, and any input containing characters outside
        // the hostname/IP alphabet must be rejected — not silently
        // treated as a hostname.
        for input in ["", ".", "foo bar", "foo/bar", "foo_bar"] {
            assert_eq!(
                host(input).unwrap_err(),
                CanonError::BadHost,
                "input={input:?}"
            );
        }
    }

    // -----------------------------------------------------------------
    // known_v4
    // -----------------------------------------------------------------

    #[test]
    fn known_v4_maps_recognized_endpoints() {
        let cases: &[(&str, u16, Destination)] = &[
            (constants::IMDS_IP, constants::IMDS_PORT, Destination::Imds),
            (
                constants::WIRE_SERVER_IP,
                constants::WIRE_SERVER_PORT,
                Destination::WireServer,
            ),
            (
                constants::WIRE_SERVER_IP,
                constants::GA_PLUGIN_PORT,
                Destination::HostGaPlugin,
            ),
        ];
        for (addr, port, expected) in cases {
            assert_eq!(
                known_v4(ip(addr), *port),
                Some(expected.clone()),
                "ip={addr}, port={port}"
            );
        }
    }

    #[test]
    fn known_v4_returns_none_for_misses() {
        // Correct IP / wrong port and any unrelated IP must not be
        // promoted to a known destination.
        let cases: &[(&str, u16)] = &[
            (constants::IMDS_IP, 8080),
            (constants::WIRE_SERVER_IP, 8080),
            ("8.8.8.8", constants::IMDS_PORT),
            ("127.0.0.1", constants::IMDS_PORT),
        ];
        for (addr, port) in cases {
            assert_eq!(known_v4(ip(addr), *port), None, "ip={addr}, port={port}");
        }
    }

    // -----------------------------------------------------------------
    // classify (URI-level entrypoint)
    // -----------------------------------------------------------------

    #[test]
    fn classify_resolves_known_destinations() {
        // (url, expected). Covers default-port inference for IMDS,
        // explicit-port forms, WireServer, HostGA, and the IPv4-mapped
        // IPv6 projection (pentest C7).
        let cases: &[(&str, Destination)] = &[
            ("http://169.254.169.254/x", Destination::Imds),
            ("http://169.254.169.254:80/x", Destination::Imds),
            ("http://168.63.129.16:80/x", Destination::WireServer),
            ("http://168.63.129.16:32526/x", Destination::HostGaPlugin),
            (
                "http://[::ffff:169.254.169.254]/x",
                Destination::Imds,
            ),
        ];
        for (url, expected) in cases {
            assert_eq!(classify(&uri(url)).unwrap(), *expected, "url={url}");
        }
    }

    #[test]
    fn classify_falls_back_to_unknown_for_unrecognized_targets() {
        // IMDS IP on the wrong port must NOT inherit the IMDS variant.
        match classify(&uri("http://169.254.169.254:8080/x")).unwrap() {
            Destination::Unknown {
                family: AddrFamily::V4,
                ip: Some(IpAddr::V4(v4)),
                port: 8080,
                ..
            } => assert_eq!(v4, ip(constants::IMDS_IP)),
            other => panic!("expected Unknown V4 on port 8080, got {other:?}"),
        }

        // Arbitrary public IP -> Unknown V4 with host_text preserved.
        match classify(&uri("http://1.2.3.4/x")).unwrap() {
            Destination::Unknown {
                family: AddrFamily::V4,
                ip: Some(IpAddr::V4(v4)),
                host_text: Some(_),
                ..
            } => assert_eq!(v4, Ipv4Addr::new(1, 2, 3, 4)),
            other => panic!("expected Unknown V4, got {other:?}"),
        }

        // Hostname -> Unknown Name with host_text preserved (no DNS).
        match classify(&uri("http://metadata.azure.internal/x")).unwrap() {
            Destination::Unknown {
                family: AddrFamily::Name,
                ip: None,
                host_text: Some(s),
                ..
            } => assert_eq!(s, "metadata.azure.internal"),
            other => panic!("expected Unknown Name, got {other:?}"),
        }

        // Non-mapped IPv6 -> Unknown V6.
        match classify(&uri("http://[::1]/x")).unwrap() {
            Destination::Unknown {
                family: AddrFamily::V6,
                ip: Some(IpAddr::V6(v6)),
                ..
            } => assert_eq!(v6, Ipv6Addr::LOCALHOST),
            other => panic!("expected Unknown V6, got {other:?}"),
        }

        // Origin-form (no authority) -> stub Unknown with no info.
        let origin_form: Uri = "/metadata/identity".parse().unwrap();
        match classify(&origin_form).unwrap() {
            Destination::Unknown {
                family: AddrFamily::Name,
                ip: None,
                port: 0,
                host_text: None,
            } => {}
            other => panic!("expected stub Unknown for origin-form, got {other:?}"),
        }
    }

    #[test]
    fn classify_rejects_bad_inputs() {
        // (url, expected error). Userinfo smuggling and host text with
        // characters outside the hostname/IP alphabet.
        let cases: &[(&str, CanonError)] = &[
            ("http://user@169.254.169.254/x", CanonError::UserinfoPresent),
            ("http://foo_bar/x", CanonError::BadHost),
        ];
        for (url, expected) in cases {
            assert_eq!(classify(&uri(url)).unwrap_err(), *expected, "url={url}");
        }
    }

    // -----------------------------------------------------------------
    // Display
    // -----------------------------------------------------------------

    #[test]
    fn display_strings_are_stable() {
        // These strings appear in audit logs; pin them so a rename
        // doesn't silently break downstream log consumers.
        let cases: &[(Destination, &str)] = &[
            (Destination::Imds, "imds"),
            (Destination::WireServer, "wireserver"),
            (Destination::HostGaPlugin, "hostga"),
            (
                Destination::Unknown {
                    family: AddrFamily::Name,
                    ip: None,
                    port: 0,
                    host_text: None,
                },
                "unknown",
            ),
        ];
        for (dest, expected) in cases {
            assert_eq!(&format!("{dest}"), expected);
        }
    }

    // -----------------------------------------------------------------
    // Appendix A.2 — host golden vectors + end-to-end classification
    //
    // Spec-conformance tests for destination classification. Vector
    // labels (`A2.xxx`) appear in every failure message so a regression
    // points straight back to the row in `Innovation-2.1-canonical-request.md`.
    //
    // These call the full canonicalize_str() entrypoint rather than
    // classify() directly so the assertion target matches what a caller
    // would see — the assertion target is still the destination output.
    // -----------------------------------------------------------------

    fn dest_via_pipeline(url: &str) -> Destination {
        super::super::canonicalize_str(url).unwrap().destination
    }

    #[test]
    fn appendix_a2_host_vectors_classify_as_imds() {
        // Every numeric / packed / IPv4-mapped-IPv6 form of
        // 169.254.169.254 must classify to Destination::Imds — this is
        // the SSRF-defeating contract that justifies the whole module's
        // existence.
        let cases: &[(&str, &str)] = &[
            ("A2.dotted_quad", "http://169.254.169.254/x"),
            ("A2.decimal_32bit", "http://2852039166/x"),
            ("A2.hex_packed", "http://0xa9fea9fe/x"),
            ("A2.octal_quad", "http://0251.0376.0251.0376/x"),
            (
                "A2.ipv4_mapped_dotted",
                "http://[::ffff:169.254.169.254]/x",
            ),
            ("A2.ipv4_mapped_hex", "http://[::ffff:a9fe:a9fe]/x"),
            // Explicit :80 — must still classify as IMDS (default port).
            ("A2.explicit_default_port", "http://169.254.169.254:80/x"),
        ];
        for (label, url) in cases {
            assert_eq!(dest_via_pipeline(url), Destination::Imds, "vector={label}");
        }
    }

    #[test]
    fn hostnames_classify_as_unknown_for_dns_rebinding_defense() {
        // Hostnames are NEVER trusted — even one that resolves to IMDS
        // at runtime must canonicalize to Unknown (with host_text
        // preserved for audit). This is the OWASP DNS-rebinding
        // defense.
        match dest_via_pipeline("http://metadata.azure.internal/x") {
            Destination::Unknown {
                host_text: Some(s), ..
            } => assert!(
                s.contains("metadata.azure.internal"),
                "host_text must preserve original hostname for audit, got {s:?}"
            ),
            d => panic!("expected Unknown with host_text, got {d:?}"),
        }
    }

    #[test]
    fn destination_classified_by_host_and_port() {
        // WireServer and HostGAPlugin share an IP but differ by port —
        // pin both the default-port and the :32526 branch.
        let cases: &[(&str, &str, Destination)] = &[
            (
                "wireserver default port",
                "http://168.63.129.16/x",
                Destination::WireServer,
            ),
            (
                "wireserver explicit :80",
                "http://168.63.129.16:80/x",
                Destination::WireServer,
            ),
            (
                "hostgaplugin on :32526",
                "http://168.63.129.16:32526/x",
                Destination::HostGaPlugin,
            ),
        ];
        for (label, url, expected) in cases {
            assert_eq!(dest_via_pipeline(url), *expected, "{label}");
        }
    }
}


