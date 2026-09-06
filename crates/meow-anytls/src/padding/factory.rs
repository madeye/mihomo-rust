use crate::padding::CHECK_MARK;
use crate::util::StringMap;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Default padding scheme
pub const DEFAULT_PADDING_SCHEME: &str = r#"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000"#;

/// PaddingFactory generates padding sizes according to the scheme
#[derive(Debug, Clone)]
pub struct PaddingFactory {
    sizes: HashMap<String, Vec<PaddingSize>>,
    raw_scheme: Vec<u8>,
    stop: u32,
    md5: String,
}

// Authentication and Waste frames encode lengths as u16. Bound the aggregate
// too: a short peer-supplied scheme must not expand one write without limit.
const MAX_PACKET_PADDING: usize = 1024 * 1024;

#[derive(Debug, Clone)]
enum PaddingSize {
    Check,
    Range(u16, u16),
}

/// The built-in default scheme, parsed once. Immutable: a scheme pushed by one
/// server must not leak into sessions of another, so runtime updates go to the
/// per-client `SharedPaddingFactory` cell instead.
static DEFAULT_FACTORY: std::sync::OnceLock<Arc<PaddingFactory>> = std::sync::OnceLock::new();

/// A padding factory that the peer can replace while a session is running.
///
/// An AnyTLS server answers any session whose advertised `padding-md5` differs
/// from its own scheme with an `UpdatePaddingScheme` frame. One cell is shared
/// by a client and every session it opens, so a pushed scheme applies to the
/// live session and to sessions opened later — the same ownership anytls-go
/// gets from handing its sessions the client's
/// `atomic.TypedValue[*padding.PaddingFactory]`.
pub type SharedPaddingFactory = Arc<RwLock<Arc<PaddingFactory>>>;

impl PaddingFactory {
    /// Create a new PaddingFactory from raw scheme bytes
    pub fn new(raw_scheme: &[u8]) -> Result<Self, String> {
        let scheme = StringMap::from_bytes(raw_scheme);

        let stop = scheme
            .get("stop")
            .ok_or_else(|| "missing 'stop' in padding scheme".to_string())?
            .parse::<u32>()
            .map_err(|_| "invalid 'stop' value".to_string())?;

        let mut sizes = HashMap::new();
        for (key, spec) in scheme.iter() {
            if key.parse::<u32>().is_err() {
                continue;
            }
            let mut packet_sizes = Vec::new();
            let mut total = 0usize;
            for part in spec.split(',').map(str::trim) {
                if part == "c" {
                    packet_sizes.push(PaddingSize::Check);
                    continue;
                }
                let (min, max) = part
                    .split_once('-')
                    .ok_or_else(|| "invalid padding range".to_string())?;
                let parse_size = |value: &str| {
                    value
                        .trim()
                        .parse::<u16>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or_else(|| "padding size must be between 1 and 65535".to_string())
                };
                let (min, max) = (parse_size(min)?, parse_size(max)?);
                let (min, max) = (min.min(max), min.max(max));
                // Each size can produce a Waste frame as well as its payload.
                total += usize::from(max) + crate::protocol::HEADER_OVERHEAD_SIZE;
                if total > MAX_PACKET_PADDING {
                    return Err("padding for one packet exceeds 1 MiB".to_string());
                }
                packet_sizes.push(PaddingSize::Range(min, max));
            }
            sizes.insert(key.clone(), packet_sizes);
        }

        let md5_hash = md5::compute(raw_scheme);
        let md5 = format!("{:x}", md5_hash);

        Ok(Self {
            sizes,
            raw_scheme: raw_scheme.to_vec(),
            stop,
            md5,
        })
    }

    /// Get the default padding factory
    ///
    /// Note: This is not the `Default` trait implementation to avoid confusion
    /// with creating a new factory. This returns a shared singleton instance.
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Arc<Self> {
        DEFAULT_FACTORY
            .get_or_init(|| {
                Arc::new(
                    Self::new(DEFAULT_PADDING_SCHEME.as_bytes())
                        .expect("default padding scheme should be valid"),
                )
            })
            .clone()
    }

    /// Wrap this factory in a cell that a client and its sessions share.
    pub fn into_shared(self: Arc<Self>) -> SharedPaddingFactory {
        Arc::new(RwLock::new(self))
    }

    /// Get the stop value
    pub fn stop(&self) -> u32 {
        self.stop
    }

    /// Get the MD5 hash of the scheme
    pub fn md5(&self) -> &str {
        &self.md5
    }

    /// Get the raw scheme bytes
    pub fn raw_scheme(&self) -> &[u8] {
        &self.raw_scheme
    }

    /// Generate record payload sizes for a given packet number
    /// Returns a vector of sizes, where CHECK_MARK (-1) indicates a check point
    pub fn generate_record_payload_sizes(&self, pkt: u32) -> Vec<i32> {
        let key = pkt.to_string();
        let Some(spec) = self.sizes.get(&key) else {
            return Vec::new();
        };
        spec.iter()
            .map(|size| match *size {
                PaddingSize::Check => CHECK_MARK,
                PaddingSize::Range(min, max) if min == max => i32::from(min),
                PaddingSize::Range(min, max) => i32::from(rand::random_range(min..=max)),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_factory() {
        let factory = PaddingFactory::default();
        assert_eq!(factory.stop(), 8);
        assert!(!factory.md5().is_empty());
    }

    #[test]
    fn test_generate_sizes() {
        let factory = PaddingFactory::default();

        // Packet 0 should be 30-30 (fixed)
        let sizes = factory.generate_record_payload_sizes(0);
        assert_eq!(sizes, vec![30]);

        // Packet 1 should be 100-400 (random in range)
        let sizes = factory.generate_record_payload_sizes(1);
        assert_eq!(sizes.len(), 1);
        assert!(sizes[0] >= 100 && sizes[0] <= 400);
    }

    #[test]
    fn test_check_mark() {
        let scheme = r#"stop=3
2=400-500,c,500-1000"#;
        let factory = PaddingFactory::new(scheme.as_bytes()).unwrap();
        let sizes = factory.generate_record_payload_sizes(2);

        assert!(sizes.len() >= 3);
        assert!(sizes[0] >= 400 && sizes[0] <= 500);
        assert_eq!(sizes[1], CHECK_MARK);
        assert!(sizes[2] >= 500 && sizes[2] <= 1000);
    }

    #[test]
    fn rejects_unrepresentable_or_malformed_sizes() {
        for range in [
            "2147483648-2147483648",
            "65536-65536",
            "1-65536",
            "-1-30",
            "0-30",
            "30",
            "x-30",
        ] {
            for packet in [0, 1] {
                let scheme = format!("stop=2\n{packet}={range}");
                assert!(PaddingFactory::new(scheme.as_bytes()).is_err(), "{scheme}");
            }
        }
    }

    #[test]
    fn accepts_wire_boundary_reversed_ranges_and_checkpoints() {
        let factory = PaddingFactory::new(b"stop=2\n0=65535-65535\n1=2-1,c,9-9").unwrap();
        assert_eq!(factory.generate_record_payload_sizes(0), vec![65535]);
        let sizes = factory.generate_record_payload_sizes(1);
        assert!((1..=2).contains(&sizes[0]));
        assert_eq!(&sizes[1..], &[CHECK_MARK, 9]);
    }

    #[test]
    fn bounds_total_padding_per_packet() {
        let sizes = ["65535-65535"; 17].join(",");
        let scheme = format!("stop=2\n1={sizes}");
        assert!(PaddingFactory::new(scheme.as_bytes()).is_err());
    }

    #[test]
    fn test_md5_hash() {
        let factory1 = PaddingFactory::default();
        let factory2 = PaddingFactory::new(DEFAULT_PADDING_SCHEME.as_bytes()).unwrap();

        assert_eq!(factory1.md5(), factory2.md5());
    }
}
