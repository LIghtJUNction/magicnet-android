use super::*;
use crate::subscriptions::{
    canonical_subscription_source_url, canonical_subscription_url, normalized_subscription_text,
    validate_subscription_url,
};
use crate::test_support::temp_app;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};

fn addresses(values: &[&str]) -> HashSet<IpAddr> {
    values.iter().map(|value| value.parse().unwrap()).collect()
}

fn origin(value: &str) -> Origin {
    Origin::parse(value).unwrap()
}

fn save(app: &App, text: &str) -> Result<(), String> {
    sub_trust(
        app,
        &[
            "sub".into(),
            "trust".into(),
            "set".into(),
            crate::encode_base64(text.as_bytes()),
        ],
    )
}

#[test]
fn trusted_sources_are_off_without_explicit_policy() {
    let app = temp_app();
    let policy = SubscriptionTrust::load(&app).unwrap();
    for url in [
        "http://nas.example:25500",
        "https://192.168.1.2",
        "https://[::1]",
        "http://100.100.1.2",
    ] {
        assert!(
            policy.check_source(&origin(url).authority()).is_err(),
            "{url}"
        );
    }
    policy
        .check_source(&origin("https://example.com").authority())
        .unwrap();
    assert!(sub_check_source(
        &app,
        &[
            "sub".into(),
            "check-source".into(),
            "http".into(),
            "nas.example".into(),
            "25500".into()
        ]
    )
    .is_err());
}

#[test]
fn trusted_networks_are_subnets_of_local_unicast_ranges() {
    for cidr in [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.1.0/24",
        "100.64.0.0/10",
        "127.0.0.1/32",
        "fc00::/7",
        "fd7a:115c:a1e0::/48",
        "::1/128",
        "::ffff:192.168.1.0/120",
    ] {
        assert!(Network::parse(cidr).is_ok(), "{cidr}");
    }
    for cidr in [
        "0.0.0.0/0",
        "10.0.0.0/7",
        "100.0.0.0/8",
        "172.0.0.0/8",
        "192.168.1.3/24",
        "1.1.1.1/32",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "192.0.2.0/24",
        "127.0.0.1/33",
        "::/0",
        "fe80::/10",
        "ff00::/8",
        "2001:4860::/32",
        "fc00::/6",
        "::1/127",
        "::/128",
        "::ffff:127.0.0.1/95",
        "::ffff:127.0.0.1/129",
        "127.1/32",
    ] {
        assert!(Network::parse(cidr).is_err(), "{cidr}");
    }
}

#[test]
fn trusted_origin_and_cidr_both_must_match() {
    let policy = SubscriptionTrust::parse(
        "http://NAS.example:25500 100.100.1.2/32\nhttp://nas.example:25500 fd7a:115c:a1e0::/48\n",
    )
    .unwrap();
    let source = origin("http://nas.example:25500");
    let allowed = addresses(&["100.100.1.2", "fd7a:115c:a1e0::2"]);
    assert_eq!(
        policy
            .authorize_addresses(&source, &source, &allowed)
            .unwrap(),
        "direct"
    );
    for values in [
        vec![],
        vec!["100.100.1.3"],
        vec!["100.100.1.2", "1.1.1.1"],
        vec!["100.100.1.2", "127.0.0.1"],
        vec!["100.100.1.2", "fd00::1"],
    ] {
        assert!(policy
            .authorize_addresses(&source, &source, &addresses(&values))
            .is_err());
    }
    for url in [
        "http://other.example:25500",
        "http://nas.example:25501",
        "https://nas.example:25500",
    ] {
        assert!(
            policy
                .authorize_addresses(&source, &origin(url), &allowed)
                .is_err(),
            "{url}"
        );
    }
}

#[test]
fn public_redirects_cannot_acquire_local_trust_or_proxy_route() {
    let policy =
        SubscriptionTrust::parse("https://nas.example 100.100.1.2/32 socks5://127.0.0.1:7892\n")
            .unwrap();
    let public = origin("https://public.example");
    let nas = origin("https://nas.example");
    assert!(policy
        .authorize_addresses(&public, &nas, &addresses(&["100.100.1.2"]))
        .is_err());
    assert_eq!(
        policy
            .authorize_addresses(&public, &nas, &addresses(&["1.1.1.1"]))
            .unwrap(),
        "direct"
    );
    assert!(policy
        .authorize_addresses(
            &public,
            &origin("http://public.example"),
            &addresses(&["1.1.1.1"])
        )
        .is_err());
    assert!(policy
        .authorize_addresses(&nas, &public, &addresses(&["1.1.1.1"]))
        .is_err());
}

#[test]
fn ipv4_mapped_answers_use_the_embedded_ipv4_policy() {
    let policy = SubscriptionTrust::parse("http://nas.example:25500 100.100.1.2/32\n").unwrap();
    let source = origin("http://nas.example:25500");
    policy
        .authorize_addresses(&source, &source, &addresses(&["::ffff:100.100.1.2"]))
        .unwrap();
    assert!(policy
        .authorize_addresses(&source, &source, &addresses(&["::ffff:127.0.0.1"]))
        .is_err());
    assert!(policy
        .authorize_addresses(&source, &source, &addresses(&["::ffff:1.1.1.1"]))
        .is_err());
}

#[test]
fn proxy_is_explicit_loopback_socks5_with_local_resolution() {
    for proxy in ["socks5://127.0.0.1:7892", "socks5://[::1]:7892"] {
        let policy = SubscriptionTrust::parse(&format!(
            "http://nas.example:25500 100.100.1.2/32 {proxy}\n"
        ))
        .unwrap();
        let source = origin("http://nas.example:25500");
        assert_eq!(
            policy
                .authorize_addresses(&source, &source, &addresses(&["100.100.1.2"]))
                .unwrap(),
            proxy
        );
    }
    for proxy in [
        "socks5h://127.0.0.1:7892",
        "http://127.0.0.1:7892",
        "socks5://192.168.1.1:7892",
        "socks5://localhost:7892",
        "socks5://127.0.0.1",
        "socks5://127.0.0.1:0",
        "socks5://127.0.0.1:65536",
        "socks5://user:secret@127.0.0.1:7892",
        "socks5://127.0.0.1:7892/",
        "socks5://127.0.0.1:7892?q=secret",
        "socks5://127.0.0.1:7892#x",
        "direct",
    ] {
        assert!(
            SubscriptionTrust::parse(&format!(
                "http://nas.example:25500 100.100.1.2/32 {proxy}\n"
            ))
            .is_err(),
            "{proxy}"
        );
    }
    assert!(SubscriptionTrust::parse("http://nas.example:25500 100.100.1.2/32\nhttp://nas.example:25500 fd00::/8 socks5://127.0.0.1:7892\n").is_err());
}

#[test]
fn policy_rejects_wildcards_credentials_paths_and_malformed_origins() {
    for value in [
        "http://*.example:25500",
        "http://nas.example:25500/sub",
        "http://nas.example:25500/",
        "http://nas.example:25500?token=SECRET",
        "http://nas.example:25500#x",
        "http://user:SECRET@nas.example:25500",
        "file://nas.example:25500",
        "http://127.1:25500",
        "http://0x7f000001:25500",
        "http://nas.example:",
        "http://nas.example:65536",
        "http://[::1]x:25500",
    ] {
        let error = SubscriptionTrust::parse(&format!("{value} 127.0.0.1/32\n"))
            .err()
            .unwrap();
        assert_eq!(error, POLICY_ERROR);
        assert!(!error.contains("SECRET"));
    }
    assert!(SubscriptionTrust::parse("http://127.0.0.1:25500 100.100.1.2/32\n").is_err());
    assert!(
        SubscriptionTrust::parse("http://nas.example:25500 100.100.1.2/32 extra extra\n").is_err()
    );
    assert!(SubscriptionTrust::parse(&"x".repeat(MAX_TRUST_BYTES + 1)).is_err());
    let rows = (1..=MAX_TRUST_ENTRIES + 1)
        .map(|i| format!("http://nas-{i}.example:25500 100.100.1.2/32\n"))
        .collect::<String>();
    assert!(SubscriptionTrust::parse(&rows).is_err());
}

#[test]
fn subscription_normalization_preserves_scheme_and_does_not_change_generic_download_policy() {
    let app = temp_app();
    save(
        &app,
        "http://NAS.example:80 100.100.1.2/32\nhttps://127.0.0.1:8443 127.0.0.1/32\n",
    )
    .unwrap();
    let url = "HTTP://NAS.example:080/sub?token=秘密#fragment";
    let expected = "http://nas.example/sub?token=%E7%A7%98%E5%AF%86";
    assert_eq!(
        canonical_subscription_source_url(&app, url).unwrap(),
        expected
    );
    assert_eq!(
        normalized_subscription_text(&app, &format!("{url}\n{expected}\n")).unwrap(),
        format!("{expected}\n")
    );
    canonical_subscription_source_url(&app, "https://127.0.0.1:8443/sub").unwrap();
    for url in ["http://NAS.example/sub", "https://127.0.0.1:8443/sub"] {
        assert!(validate_subscription_url(url).is_err());
        assert!(canonical_subscription_url(url).is_err());
    }
    assert!(canonical_subscription_source_url(&app, "http://other.example/sub").is_err());
    assert!(canonical_subscription_source_url(&app, "https://127.0.0.1/sub").is_err());
}

#[test]
fn trust_is_saved_atomically_and_revocation_is_immediate() {
    let app = temp_app();
    let source = origin("http://nas.example:25500");
    save(
        &app,
        "# explicitly trusted\nHTTP://NAS.example:25500 100.100.1.2/32\n",
    )
    .unwrap();
    let path = app.moddir.join(TRUST_PATH);
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "http://nas.example:25500 100.100.1.2/32\n"
    );
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    SubscriptionTrust::load(&app)
        .unwrap()
        .check_source(&source.authority())
        .unwrap();
    let before = fs::read(&path).unwrap();
    assert!(save(&app, "http://nas.example:25500 0.0.0.0/0\n").is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    sub_trust(&app, &["sub".into(), "trust".into(), "clear".into()]).unwrap();
    assert!(SubscriptionTrust::load(&app)
        .unwrap()
        .check_source(&source.authority())
        .is_err());
    assert!(fs::read(&path).unwrap().is_empty());
}

#[test]
fn unsafe_or_corrupt_policy_fails_closed() {
    let app = temp_app();
    let path = app.moddir.join(TRUST_PATH);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let outside = app.moddir.join("outside");
    fs::write(&outside, "http://nas.example 100.100.1.2/32\n").unwrap();
    symlink(&outside, &path).unwrap();
    assert!(SubscriptionTrust::load(&app).is_err());
    assert!(save(&app, "http://nas.example 100.100.1.2/32\n").is_err());
    fs::remove_file(&path).unwrap();
    fs::write(&path, "http://nas.example 0.0.0.0/0\n").unwrap();
    assert!(SubscriptionTrust::load(&app).is_err());
    assert!(canonical_subscription_source_url(&app, "https://public.example/sub").is_err());
}

#[test]
fn trust_changes_share_subscription_serialization_and_recovery_guard() {
    let app = temp_app();
    let guard = SubscriptionSourceGuard::acquire(&app).unwrap();
    assert!(save(&app, "http://nas.example 100.100.1.2/32\n").is_err());
    assert!(!app.moddir.join(TRUST_PATH).exists());
    drop(guard);
    fs::create_dir_all(app.moddir.join(".state/sing-box/subscription-transaction")).unwrap();
    assert!(save(&app, "http://nas.example 100.100.1.2/32\n").is_err());
    assert!(!app.moddir.join(TRUST_PATH).exists());
}

#[test]
fn resolver_validates_literal_destinations_without_using_dns() {
    let app = temp_app();
    save(
        &app,
        "http://127.0.0.1:25500 127.0.0.1/32 socks5://127.0.0.1:7892\n",
    )
    .unwrap();
    let args = [
        "sub",
        "resolve-source",
        "http",
        "127.0.0.1",
        "25500",
        "http",
        "127.0.0.1",
        "25500",
    ]
    .map(str::to_string);
    sub_resolve_source(&app, &args).unwrap();
    let mut changed = args.clone();
    changed[3] = "127.0.0.2".to_string();
    assert!(sub_resolve_source(&app, &changed).is_err());
    assert!(sub_resolve_source(&app, &args[..7]).is_err());
}
