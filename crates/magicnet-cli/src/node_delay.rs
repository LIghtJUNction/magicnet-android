use serde_json::Value;

pub(crate) fn node_delay(app: &crate::App, name: &str) -> Result<i64, String> {
    let clean = name.trim();
    if clean.is_empty() {
        return Err("node name is empty".to_string());
    }
    let endpoint = delay_endpoint(&app.api, clean);
    let path = endpoint
        .strip_prefix(&app.api)
        .expect("local delay endpoint");
    let body = crate::webui_api::api_response(app, "GET", path, "", 7, 1024 * 1024)?;
    parse_delay(&String::from_utf8_lossy(&body))
}

fn delay_endpoint(api: &str, name: &str) -> String {
    format!(
        "{api}/proxies/{}/delay?timeout=5000&url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204",
        encode_path_segment(name)
    )
}

pub(crate) fn encode_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            output.push(byte as char);
        } else {
            output.push('%');
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 15) as usize] as char);
        }
    }
    output
}

fn parse_delay(text: &str) -> Result<i64, String> {
    let json: Value = serde_json::from_str(text).map_err(|err| format!("parse delay: {err}"))?;
    json.get("delay")
        .and_then(Value::as_i64)
        .or_else(|| json.get("latency").and_then(Value::as_i64))
        .ok_or_else(|| format!("delay is not reported: {text}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_name_is_encoded_as_path_segment_for_delay_api() {
        assert_eq!(encode_path_segment("HK 01/relay"), "HK%2001%2Frelay");
        assert_eq!(encode_path_segment("jp-1_~"), "jp-1_~");
    }

    #[test]
    fn delay_endpoint_uses_the_configured_local_api() {
        assert_eq!(
            delay_endpoint("http://127.0.0.1:19090", "HK 01/relay"),
            "http://127.0.0.1:19090/proxies/HK%2001%2Frelay/delay?timeout=5000&url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204"
        );
    }

    #[test]
    fn parses_delay_and_latency_fields() {
        assert_eq!(parse_delay(r#"{"delay":123}"#).unwrap(), 123);
        assert_eq!(parse_delay(r#"{"latency":234}"#).unwrap(), 234);
    }
}
