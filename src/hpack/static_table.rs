//! HPACK static table (RFC 7541 Appendix A).
//!
//! 61 pre-defined header field entries, indexed 1 through 61.
//! Index 0 is unused in the wire format; we store entries 1..=61 at array
//! positions 0..61 and adjust indices on lookup.

/// A single entry in the static table.
#[derive(Debug, Clone, Copy)]
pub struct StaticEntry {
    pub name: &'static [u8],
    pub value: &'static [u8],
}

/// Result of a static table lookup.
pub enum LookupResult {
    /// Exact match (name + value). Contains the 1-based index.
    ExactMatch(usize),
    /// Name-only match. Contains the 1-based index.
    NameMatch(usize),
    /// No match.
    NotFound,
}

/// The HPACK static table (61 entries, 1-indexed on wire, stored 0-indexed).
pub static STATIC_TABLE: [StaticEntry; 61] = [
    StaticEntry {
        name: b":authority",
        value: b"",
    }, //  1
    StaticEntry {
        name: b":method",
        value: b"GET",
    }, //  2
    StaticEntry {
        name: b":method",
        value: b"POST",
    }, //  3
    StaticEntry {
        name: b":path",
        value: b"/",
    }, //  4
    StaticEntry {
        name: b":path",
        value: b"/index.html",
    }, //  5
    StaticEntry {
        name: b":scheme",
        value: b"http",
    }, //  6
    StaticEntry {
        name: b":scheme",
        value: b"https",
    }, //  7
    StaticEntry {
        name: b":status",
        value: b"200",
    }, //  8
    StaticEntry {
        name: b":status",
        value: b"204",
    }, //  9
    StaticEntry {
        name: b":status",
        value: b"206",
    }, // 10
    StaticEntry {
        name: b":status",
        value: b"304",
    }, // 11
    StaticEntry {
        name: b":status",
        value: b"400",
    }, // 12
    StaticEntry {
        name: b":status",
        value: b"404",
    }, // 13
    StaticEntry {
        name: b":status",
        value: b"500",
    }, // 14
    StaticEntry {
        name: b"accept-charset",
        value: b"",
    }, // 15
    StaticEntry {
        name: b"accept-encoding",
        value: b"gzip, deflate",
    }, // 16
    StaticEntry {
        name: b"accept-language",
        value: b"",
    }, // 17
    StaticEntry {
        name: b"accept-ranges",
        value: b"",
    }, // 18
    StaticEntry {
        name: b"accept",
        value: b"",
    }, // 19
    StaticEntry {
        name: b"access-control-allow-origin",
        value: b"",
    }, // 20
    StaticEntry {
        name: b"age",
        value: b"",
    }, // 21
    StaticEntry {
        name: b"allow",
        value: b"",
    }, // 22
    StaticEntry {
        name: b"authorization",
        value: b"",
    }, // 23
    StaticEntry {
        name: b"cache-control",
        value: b"",
    }, // 24
    StaticEntry {
        name: b"content-disposition",
        value: b"",
    }, // 25
    StaticEntry {
        name: b"content-encoding",
        value: b"",
    }, // 26
    StaticEntry {
        name: b"content-language",
        value: b"",
    }, // 27
    StaticEntry {
        name: b"content-length",
        value: b"",
    }, // 28
    StaticEntry {
        name: b"content-location",
        value: b"",
    }, // 29
    StaticEntry {
        name: b"content-range",
        value: b"",
    }, // 30
    StaticEntry {
        name: b"content-type",
        value: b"",
    }, // 31
    StaticEntry {
        name: b"cookie",
        value: b"",
    }, // 32
    StaticEntry {
        name: b"date",
        value: b"",
    }, // 33
    StaticEntry {
        name: b"etag",
        value: b"",
    }, // 34
    StaticEntry {
        name: b"expect",
        value: b"",
    }, // 35
    StaticEntry {
        name: b"expires",
        value: b"",
    }, // 36
    StaticEntry {
        name: b"from",
        value: b"",
    }, // 37
    StaticEntry {
        name: b"host",
        value: b"",
    }, // 38
    StaticEntry {
        name: b"if-match",
        value: b"",
    }, // 39
    StaticEntry {
        name: b"if-modified-since",
        value: b"",
    }, // 40
    StaticEntry {
        name: b"if-none-match",
        value: b"",
    }, // 41
    StaticEntry {
        name: b"if-range",
        value: b"",
    }, // 42
    StaticEntry {
        name: b"if-unmodified-since",
        value: b"",
    }, // 43
    StaticEntry {
        name: b"last-modified",
        value: b"",
    }, // 44
    StaticEntry {
        name: b"link",
        value: b"",
    }, // 45
    StaticEntry {
        name: b"location",
        value: b"",
    }, // 46
    StaticEntry {
        name: b"max-forwards",
        value: b"",
    }, // 47
    StaticEntry {
        name: b"proxy-authenticate",
        value: b"",
    }, // 48
    StaticEntry {
        name: b"proxy-authorization",
        value: b"",
    }, // 49
    StaticEntry {
        name: b"range",
        value: b"",
    }, // 50
    StaticEntry {
        name: b"referer",
        value: b"",
    }, // 51
    StaticEntry {
        name: b"refresh",
        value: b"",
    }, // 52
    StaticEntry {
        name: b"retry-after",
        value: b"",
    }, // 53
    StaticEntry {
        name: b"server",
        value: b"",
    }, // 54
    StaticEntry {
        name: b"set-cookie",
        value: b"",
    }, // 55
    StaticEntry {
        name: b"strict-transport-security",
        value: b"",
    }, // 56
    StaticEntry {
        name: b"transfer-encoding",
        value: b"",
    }, // 57
    StaticEntry {
        name: b"user-agent",
        value: b"",
    }, // 58
    StaticEntry {
        name: b"vary",
        value: b"",
    }, // 59
    StaticEntry {
        name: b"via",
        value: b"",
    }, // 60
    StaticEntry {
        name: b"www-authenticate",
        value: b"",
    }, // 61
];

/// Look up a (name, value) pair in the static table.
///
/// Returns 1-based indices (matching the wire format).
pub fn lookup(name: &[u8], value: &[u8]) -> LookupResult {
    let mut name_match: Option<usize> = None;

    for (i, entry) in STATIC_TABLE.iter().enumerate() {
        if entry.name == name {
            if entry.value == value {
                return LookupResult::ExactMatch(i + 1); // 1-based
            }
            if name_match.is_none() {
                name_match = Some(i + 1);
            }
        }
    }

    match name_match {
        Some(idx) => LookupResult::NameMatch(idx),
        None => LookupResult::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_61_entries() {
        assert_eq!(STATIC_TABLE.len(), 61);
    }

    #[test]
    fn known_entries() {
        assert_eq!(STATIC_TABLE[0].name, b":authority");
        assert_eq!(STATIC_TABLE[1].name, b":method");
        assert_eq!(STATIC_TABLE[1].value, b"GET");
        assert_eq!(STATIC_TABLE[2].name, b":method");
        assert_eq!(STATIC_TABLE[2].value, b"POST");
        assert_eq!(STATIC_TABLE[7].name, b":status");
        assert_eq!(STATIC_TABLE[7].value, b"200");
    }

    #[test]
    fn lookup_exact_match() {
        match lookup(b":method", b"GET") {
            LookupResult::ExactMatch(idx) => assert_eq!(idx, 2),
            _ => panic!("expected ExactMatch"),
        }
    }

    #[test]
    fn lookup_name_match() {
        match lookup(b":status", b"201") {
            LookupResult::NameMatch(idx) => assert_eq!(idx, 8), // first :status is index 8
            _ => panic!("expected NameMatch"),
        }
    }

    #[test]
    fn lookup_not_found() {
        assert!(matches!(
            lookup(b"x-custom", b"val"),
            LookupResult::NotFound
        ));
    }
}
