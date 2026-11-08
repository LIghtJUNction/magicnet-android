use std::fs;
use std::path::Path;

use crate::service::{config_apply_lock, restart_current_core_locked};
use crate::{run_magicnet_function, write_text_file, App};

const DNS_CONF: &str = ".config/magicnet/dns.conf";
const DNS_TEST_PROXY: &str = "http://127.0.0.1:7892";

pub(crate) fn dns_cmd(app: &App, args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str).unwrap_or("status") {
        "status" => {
            dns_status(app);
            Ok(())
        }
        "set" => dns_set(app, args.get(1).map(String::as_str).unwrap_or_default()),
        "test" => dns_test(
            app,
            args.get(1).map(String::as_str).unwrap_or("www.gstatic.com"),
        ),
        "apply" => {
            let guard = config_apply_lock(app)?;
            run_magicnet_function(app, "magicnet_dns_apply")?;
            restart_current_core_locked(app, &guard)
        }
        _ => Err(dns_usage()),
    }
}

fn dns_test(app: &App, domain: &str) -> Result<(), String> {
    let domain = normalize_test_domain(domain)?;
    let url = format!("https://{domain}/");
    let output = crate::trusted_curl(app)
        // The CLI runs as uid 0, which is intentionally excluded from
        // magicnet0 to prevent proxy loops.  Force this diagnostic through
        // the local mixed inbound so it measures the running sing-box path
        // instead of bypassing the tunnel and producing a false timeout.
        .args(dns_test_curl_args(&url))
        .output()
        .map_err(|err| format!("run curl: {err}"))?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn dns_test_curl_args(url: &str) -> Vec<&str> {
    vec![
        // Root is deliberately outside the magicnet0 TUN boundary. Route the
        // probe through MagicNet's loopback mixed inbound so it exercises the
        // same managed DNS and outbound path as proxied applications.
        // A DNS/transport probe must not fail merely because a healthy
        // endpoint returns HTTP 4xx/5xx (for example, www.gstatic.com/
        // commonly returns 404). Curl still fails on DNS, connect, and TLS.
        "--noproxy",
        "",
        "-x",
        DNS_TEST_PROXY,
        "-sS",
        "--max-time",
        "6",
        "-o",
        "/dev/null",
        "-w",
        "domain=%{url_effective}\nprobe_path=magicnet-mixed\nhttp_code=%{http_code}\nproxy_ip=%{remote_ip}\ntime_total=%{time_total}\n",
        url,
    ]
}

pub(crate) fn profile_servers(profile: &str) -> (&'static str, Option<&'static str>, &'static str) {
    match profile {
        "cloudflare-udp" => ("1.1.1.1", Some("1.0.0.1"), "udp"),
        "cloudflare-dot" => ("tls://1.1.1.1", Some("tls://1.0.0.1"), "dot"),
        "cloudflare-doh" => (
            "https://cloudflare-dns.com/dns-query",
            Some("https://1.0.0.1/dns-query"),
            "doh",
        ),
        _ => ("doh-cloudflare", None, "default"),
    }
}

fn dns_status(app: &App) {
    let profile = dns_profile(app);
    let (primary, secondary, transport) = profile_servers(&profile);
    println!("profile={profile}");
    println!("primary={primary}");
    if let Some(secondary) = secondary {
        println!("secondary={secondary}");
    }
    println!("transport={transport}");
}

fn dns_set(app: &App, profile: &str) -> Result<(), String> {
    let profile = normalize_profile(profile)?;
    let guard = config_apply_lock(app)?;
    apply_dns_profile(app, profile)?;
    restart_current_core_locked(app, &guard)?;
    println!("[info] DNS profile set to {profile}");
    Ok(())
}

fn apply_dns_profile(app: &App, profile: &str) -> Result<(), String> {
    let path = Path::new(DNS_CONF);
    let previous = crate::utils::read_module_text_bounded(app, path, 64 * 1024)?;
    write_text_file(app, path, &format!("MAGICNET_DNS_PROFILE={profile}\n"))?;
    if let Err(error) = run_magicnet_function(app, "magicnet_dns_apply") {
        let restored = match previous {
            Some(text) => write_text_file(app, path, &text),
            None => crate::utils::remove_module_file(app, path),
        };
        restored.map_err(|restore| {
            format!("DNS apply failed: {error}; saved DNS profile rollback failed: {restore}")
        })?;
        return Err(format!(
            "DNS apply failed; previous DNS profile restored: {error}"
        ));
    }
    Ok(())
}

pub(crate) fn normalize_profile(profile: &str) -> Result<&'static str, String> {
    match profile {
        "default" | "system" | "local" => Ok("default"),
        "cloudflare" | "cloudflare-doh" | "1.1.1.1-doh" | "doh" => Ok("cloudflare-doh"),
        "cloudflare-dot" | "1.1.1.1-dot" | "dot" => Ok("cloudflare-dot"),
        "cloudflare-udp" | "1.1.1.1" | "udp" => Ok("cloudflare-udp"),
        _ => Err(dns_usage()),
    }
}

fn normalize_test_domain(domain: &str) -> Result<&str, String> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() || domain.len() > 253 {
        return Err("Usage: cli dns test [domain]".to_string());
    }
    let valid = domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    if valid && domain.contains('.') {
        Ok(domain)
    } else {
        Err("Usage: cli dns test [domain]".to_string())
    }
}

fn dns_profile(app: &App) -> String {
    fs::read_to_string(app.moddir.join(DNS_CONF))
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                let (_, value) = line.split_once('=')?;
                normalize_profile(value.trim().trim_matches('"').trim_matches('\''))
                    .ok()
                    .map(ToOwned::to_owned)
            })
        })
        .unwrap_or_else(|| "default".to_string())
}

fn dns_usage() -> String {
    "Usage: cli dns {status|set <default|cloudflare-doh|cloudflare-dot|cloudflare-udp>|test [domain]|apply}"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        apply_dns_profile, dns_set, dns_test_curl_args, normalize_test_domain, DNS_CONF,
        DNS_TEST_PROXY,
    };
    use crate::test_support::{temp_app, TempApp};
    use std::fs;

    fn profile_fixture(previous: Option<&str>, apply_body: &str) -> TempApp {
        let app = temp_app();
        fs::create_dir_all(app.moddir.join(".config/magicnet")).unwrap();
        fs::create_dir_all(app.moddir.join("lib/kamfw")).unwrap();
        if let Some(previous) = previous {
            fs::write(app.moddir.join(DNS_CONF), previous).unwrap();
        }
        fs::write(app.moddir.join("lib/kamfw/.kamfwrc"), "import() { :; }\n").unwrap();
        fs::write(
            app.moddir.join("lib/magicnet.sh"),
            format!(
                "magicnet_dns_apply() {{\ncp \"$MODDIR/{DNS_CONF}\" \"$MODDIR/attempted-profile\"\n{apply_body}\n}}\nmagicnet_start_kernel() {{ touch \"$MODDIR/started\"; }}\nmagicnet_stop_kernel() {{ touch \"$MODDIR/stopped\"; }}\n"
            ),
        )
        .unwrap();
        app
    }

    #[test]
    fn dns_profile_waits_for_shared_config_owner_before_writing() {
        let original = "MAGICNET_DNS_PROFILE=cloudflare-dot\n";
        let app = profile_fixture(Some(original), "return 0");
        let _guard = crate::service::config_apply_lock(&app).unwrap();
        let error = dns_set(&app, "default").unwrap_err();
        assert!(error.contains("config apply is still busy"), "{error}");
        assert_eq!(
            fs::read_to_string(app.moddir.join(DNS_CONF)).unwrap(),
            original
        );
        assert!(!app.moddir.join("attempted-profile").exists());
    }

    #[test]
    fn failed_dns_apply_restores_exact_previous_intent_or_absence() {
        for previous in [
            None,
            Some("# original settings\r\nMAGICNET_DNS_PROFILE='cloudflare-dot'\r\n\n"),
        ] {
            let app = profile_fixture(previous, "return 42");
            let error = dns_set(&app, "default").unwrap_err();
            assert!(
                error.contains("magicnet_dns_apply failed with status 42"),
                "{error}"
            );
            assert_eq!(
                fs::read_to_string(app.moddir.join("attempted-profile")).unwrap(),
                "MAGICNET_DNS_PROFILE=default\n"
            );
            assert_eq!(
                fs::read(app.moddir.join(DNS_CONF)).ok().as_deref(),
                previous.map(str::as_bytes)
            );
            assert!(!app.moddir.join("started").exists());
            assert!(!app.moddir.join("stopped").exists());
        }
    }

    #[test]
    fn failed_dns_apply_reports_restore_failure() {
        for previous in [None, Some("MAGICNET_DNS_PROFILE=cloudflare-dot\n")] {
            let app = profile_fixture(
                previous,
                "rm \"$MODDIR/.config/magicnet/dns.conf\"\nmkdir \"$MODDIR/.config/magicnet/dns.conf\"\nreturn 42",
            );
            let error = dns_set(&app, "default").unwrap_err();
            assert!(
                error.contains("magicnet_dns_apply failed with status 42"),
                "{error}"
            );
            assert!(
                error.contains("saved DNS profile rollback failed"),
                "{error}"
            );
            assert!(!error.contains("previous DNS profile restored"), "{error}");
            assert!(!app.moddir.join("started").exists());
            assert!(!app.moddir.join("stopped").exists());
        }
    }

    #[test]
    fn successful_dns_apply_keeps_default_and_explicit_profiles() {
        for profile in [
            "default",
            "cloudflare-doh",
            "cloudflare-dot",
            "cloudflare-udp",
        ] {
            let app = profile_fixture(
                Some("# old settings\nMAGICNET_DNS_PROFILE=default\n"),
                "return 0",
            );
            apply_dns_profile(&app, profile).unwrap();
            let expected = format!("MAGICNET_DNS_PROFILE={profile}\n");
            assert_eq!(
                fs::read_to_string(app.moddir.join(DNS_CONF)).unwrap(),
                expected
            );
            assert_eq!(
                fs::read_to_string(app.moddir.join("attempted-profile")).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn dns_test_domain_rejects_urls_and_shell_fragments() {
        assert_eq!(normalize_test_domain("example.com").unwrap(), "example.com");
        assert!(normalize_test_domain("https://example.com").is_err());
        assert!(normalize_test_domain("example.com;id").is_err());
        assert!(normalize_test_domain("localhost").is_err());
    }

    #[test]
    fn dns_test_curl_uses_local_proxy_for_root_callers() {
        let args = dns_test_curl_args("https://www.gstatic.com/");
        assert!(args.windows(2).any(|pair| pair == ["--noproxy", ""]));
        assert!(args.windows(2).any(|pair| pair == ["-x", DNS_TEST_PROXY]));
        let write_out = args
            .windows(2)
            .find(|pair| pair[0] == "-w")
            .map(|pair| pair[1])
            .expect("curl write-out format");
        assert!(write_out.contains("\nprobe_path=magicnet-mixed\n"));
        assert!(write_out.contains("\nproxy_ip=%{remote_ip}\n"));
        assert!(!write_out.contains("\nremote_ip="));
    }
}
