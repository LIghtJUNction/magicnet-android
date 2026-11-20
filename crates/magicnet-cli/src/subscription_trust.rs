use super::{
    parse_subscription_port, parse_subscription_source_authority,
    validate_resolved_subscription_addresses, validate_subscription_host,
    validate_subscription_host_syntax, SubscriptionAuthority, SubscriptionSourceGuard,
};
use crate::{decode_base64, write_secret_file, App};
use std::collections::HashSet;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;

const TRUST_PATH: &str = ".config/sing-box/subscription-trust.list";
const MAX_TRUST_BYTES: usize = 16 * 1024;
const MAX_TRUST_ENTRIES: usize = 64;
const POLICY_ERROR: &str = "Invalid subscription trust policy";
const SOURCE_DENIED: &str = "Subscription source is not authorized";

#[derive(Clone, PartialEq, Eq)]
struct Origin {
    scheme: &'static str,
    host: String,
    port: u16,
}

impl Origin {
    fn from_authority(authority: &SubscriptionAuthority<'_>) -> Self {
        Self {
            scheme: authority.scheme,
            host: authority.host.parse::<IpAddr>().map_or_else(
                |_| authority.host.to_ascii_lowercase(),
                |address| address.to_canonical().to_string(),
            ),
            port: authority.port,
        }
    }

    fn from_parts(scheme: &str, host: &str, port: &str) -> Result<Self, String> {
        let scheme = if scheme.eq_ignore_ascii_case("http") {
            "http"
        } else if scheme.eq_ignore_ascii_case("https") {
            "https"
        } else {
            return Err(SOURCE_DENIED.to_string());
        };
        validate_subscription_host_syntax(host).map_err(|_| SOURCE_DENIED.to_string())?;
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(SOURCE_DENIED.to_string());
        }
        let port = parse_subscription_port(port).map_err(|_| SOURCE_DENIED.to_string())?;
        Ok(Self::from_authority(&SubscriptionAuthority {
            scheme,
            host,
            port,
        }))
    }

    fn parse(value: &str) -> Result<Self, String> {
        let (_, authority) = value.split_once("://").ok_or(POLICY_ERROR)?;
        if authority.contains(['/', '?', '#', '@', '\\']) {
            return Err(POLICY_ERROR.to_string());
        }
        let parsed = parse_subscription_source_authority(value).map_err(|_| POLICY_ERROR)?;
        Ok(Self::from_authority(&parsed))
    }

    fn authority(&self) -> SubscriptionAuthority<'_> {
        SubscriptionAuthority {
            scheme: self.scheme,
            host: &self.host,
            port: self.port,
        }
    }

    fn url(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{}://{host}:{}", self.scheme, self.port)
    }

    fn public(&self) -> Result<(), String> {
        if self.scheme != "https" {
            return Err(SOURCE_DENIED.to_string());
        }
        validate_subscription_host(&self.host).map_err(|_| SOURCE_DENIED.to_string())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Network {
    address: IpAddr,
    prefix: u32,
}

impl Network {
    fn parse(value: &str) -> Result<Self, String> {
        let (address, prefix) = value.split_once('/').ok_or(POLICY_ERROR)?;
        if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(POLICY_ERROR.to_string());
        }
        let mut prefix = prefix.parse::<u32>().map_err(|_| POLICY_ERROR)?;
        let address = address.parse::<IpAddr>().map_err(|_| POLICY_ERROR)?;
        if address.to_canonical() != address {
            prefix = prefix.checked_sub(96).ok_or(POLICY_ERROR)?;
        }
        let address = address.to_canonical();
        let network = Self { address, prefix };
        let permitted = match address {
            IpAddr::V4(ip) if prefix <= 32 => {
                let value = u32::from(ip);
                let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                value & mask == value
                    && [
                        (0x0a00_0000, 8),
                        (0xac10_0000, 12),
                        (0xc0a8_0000, 16),
                        (0x6440_0000, 10),
                        (0x7f00_0000, 8),
                    ]
                    .iter()
                    .any(|&(base, bits)| {
                        prefix >= bits && value >> (32 - bits) == base >> (32 - bits)
                    })
            }
            IpAddr::V6(ip) if prefix <= 128 => {
                let value = u128::from(ip);
                let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
                value & mask == value
                    && ((prefix >= 7 && value >> 121 == 0x7e)
                        || (prefix == 128 && ip.is_loopback()))
            }
            _ => false,
        };
        if !permitted {
            return Err(POLICY_ERROR.to_string());
        }
        Ok(network)
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix).unwrap_or(0);
                u32::from(address) & mask == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix).unwrap_or(0);
                u128::from(address) & mask == u128::from(network)
            }
            _ => false,
        }
    }

    fn text(&self) -> String {
        format!("{}/{}", self.address, self.prefix)
    }
}

fn parse_route(value: &str) -> Result<String, String> {
    let endpoint = value.strip_prefix("socks5://").ok_or(POLICY_ERROR)?;
    // A port is mandatory; the source's default HTTP port is not a proxy default.
    let (_, port) = endpoint.rsplit_once(':').ok_or(POLICY_ERROR)?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(POLICY_ERROR.to_string());
    }
    let origin = Origin::parse(&format!("http://{endpoint}"))?;
    let address = origin.host.parse::<IpAddr>().map_err(|_| POLICY_ERROR)?;
    if !address.is_loopback() {
        return Err(POLICY_ERROR.to_string());
    }
    Ok(origin.url().replacen("http://", "socks5://", 1))
}

struct TrustedSource {
    origin: Origin,
    network: Network,
    route: String,
}

pub(super) struct SubscriptionTrust {
    sources: Vec<TrustedSource>,
}

impl SubscriptionTrust {
    pub(super) fn load(app: &App) -> Result<Self, String> {
        let text = crate::utils::read_module_text_bounded(
            app,
            Path::new(TRUST_PATH),
            MAX_TRUST_BYTES as u64,
        )
        .map_err(|_| POLICY_ERROR.to_string())?
        .unwrap_or_default();
        Self::parse(&text)
    }

    fn parse(text: &str) -> Result<Self, String> {
        if text.len() > MAX_TRUST_BYTES || text.contains('\0') {
            return Err(POLICY_ERROR.to_string());
        }
        let mut sources: Vec<TrustedSource> = Vec::new();
        for line in text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if !(2..=3).contains(&fields.len()) || sources.len() >= MAX_TRUST_ENTRIES {
                return Err(POLICY_ERROR.to_string());
            }
            let origin = Origin::parse(fields[0])?;
            let network = Network::parse(fields[1])?;
            let route = fields
                .get(2)
                .map_or_else(|| Ok("direct".to_string()), |value| parse_route(value))?;
            if let Ok(address) = origin.host.parse::<IpAddr>() {
                if !network.contains(address) {
                    return Err(POLICY_ERROR.to_string());
                }
            }
            if sources
                .iter()
                .any(|source| source.origin == origin && source.route != route)
            {
                return Err(POLICY_ERROR.to_string());
            }
            if !sources
                .iter()
                .any(|source| source.origin == origin && source.network == network)
            {
                sources.push(TrustedSource {
                    origin,
                    network,
                    route,
                });
            }
        }
        Ok(Self { sources })
    }

    fn normalized(&self) -> String {
        self.sources
            .iter()
            .map(|source| {
                let route = if source.route == "direct" {
                    String::new()
                } else {
                    format!(" {}", source.route)
                };
                format!("{} {}{route}\n", source.origin.url(), source.network.text())
            })
            .collect()
    }

    fn matching<'a>(&'a self, origin: &'a Origin) -> impl Iterator<Item = &'a TrustedSource> {
        self.sources
            .iter()
            .filter(move |source| source.origin == *origin)
    }

    pub(super) fn has_origin(&self, authority: &SubscriptionAuthority<'_>) -> bool {
        self.matching(&Origin::from_authority(authority))
            .next()
            .is_some()
    }

    pub(super) fn check_source(&self, authority: &SubscriptionAuthority<'_>) -> Result<(), String> {
        let origin = Origin::from_authority(authority);
        if self.matching(&origin).next().is_none() {
            return origin.public();
        }
        if let Ok(address) = origin.host.parse::<IpAddr>() {
            if !self
                .matching(&origin)
                .any(|source| source.network.contains(address))
            {
                return Err(SOURCE_DENIED.to_string());
            }
        }
        Ok(())
    }

    fn check_hop(&self, initial: &Origin, hop: &Origin) -> Result<(), String> {
        self.check_source(&initial.authority())?;
        if self.matching(initial).next().is_some() {
            if initial != hop {
                return Err(SOURCE_DENIED.to_string());
            }
            Ok(())
        } else {
            // A public provider cannot acquire local privileges through a redirect.
            hop.public()
        }
    }

    fn authorize_addresses(
        &self,
        initial: &Origin,
        hop: &Origin,
        addresses: &HashSet<IpAddr>,
    ) -> Result<String, String> {
        self.check_hop(initial, hop)?;
        let Some(source) = self.matching(initial).next() else {
            validate_resolved_subscription_addresses(addresses)
                .map_err(|_| SOURCE_DENIED.to_string())?;
            return Ok("direct".to_string());
        };
        if addresses.is_empty()
            || addresses.iter().any(|&address| {
                !self
                    .matching(initial)
                    .any(|source| source.network.contains(address))
            })
        {
            return Err(SOURCE_DENIED.to_string());
        }
        Ok(source.route.clone())
    }
}

/// Validate intent without DNS or exposing the subscription path/query.
pub fn sub_check_source(app: &App, args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        return Err("Usage: cli sub check-source <scheme> <hostname> <port>".to_string());
    }
    let origin = Origin::from_parts(&args[2], &args[3], &args[4])?;
    SubscriptionTrust::load(app)?.check_source(&origin.authority())
}

/// Resolve and authorize the whole set before printing any destination. The
/// shell pins these IPs with curl; SOCKS5 receives the pinned IP, never a hostname.
pub fn sub_resolve_source(app: &App, args: &[String]) -> Result<(), String> {
    if args.len() != 8 {
        return Err("Usage: cli sub resolve-source <scheme> <hostname> <port> <origin-scheme> <origin-hostname> <origin-port>".to_string());
    }
    let hop = Origin::from_parts(&args[2], &args[3], &args[4])?;
    let initial = Origin::from_parts(&args[5], &args[6], &args[7])?;
    let policy = SubscriptionTrust::load(app)?;
    policy.check_hop(&initial, &hop)?;
    let addresses = (hop.host.as_str(), hop.port)
        .to_socket_addrs()
        .map_err(|_| "Subscription hostname resolution failed".to_string())?
        .map(|address| address.ip().to_canonical())
        .collect::<HashSet<_>>();
    let route = policy.authorize_addresses(&initial, &hop, &addresses)?;
    let mut addresses = addresses.into_iter().collect::<Vec<_>>();
    addresses.sort_by_key(ToString::to_string);
    for address in addresses {
        println!("{address}|{route}");
    }
    Ok(())
}

pub fn sub_trust(app: &App, args: &[String]) -> Result<(), String> {
    let text = match args.get(2).map(String::as_str) {
        Some("set") if args.len() == 4 => {
            if args[3].len() > MAX_TRUST_BYTES * 2 {
                return Err(POLICY_ERROR.to_string());
            }
            let bytes = decode_base64(&args[3]).map_err(|_| POLICY_ERROR.to_string())?;
            let text = std::str::from_utf8(&bytes).map_err(|_| POLICY_ERROR.to_string())?;
            let policy = SubscriptionTrust::parse(text)?;
            if policy.sources.is_empty() {
                return Err("Subscription trust list is empty; use clear".to_string());
            }
            policy.normalized()
        }
        Some("clear") if args.len() == 3 => String::new(),
        _ => return Err("Usage: cli sub trust {set <base64-lines>|clear}".to_string()),
    };
    let _lifecycle = crate::service::config_apply_lock(app)?;
    let _update = SubscriptionSourceGuard::acquire(app)?;
    if app
        .moddir
        .join(".state/sing-box/subscription-transaction")
        .exists()
    {
        return Err("subscription recovery is pending; retry after recovery".to_string());
    }
    write_secret_file(app, Path::new(TRUST_PATH), &text)
        .map_err(|_| "Cannot save subscription trust policy".to_string())
}

#[cfg(test)]
#[path = "../tests/internal/subscription_trust.rs"]
mod tests;
