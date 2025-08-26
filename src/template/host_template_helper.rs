use super::helpers;
use crate::models::Host;

/// Format the host name as a heading using existing helpers.
pub fn host_heading(host: &Host) -> String {
    let name = host.name.as_deref().unwrap_or("unknown");
    helpers::heading2(name)
}

/// Produce a label combining host name, IP address, and NetBIOS name if present.
pub fn host_label(host: &Host) -> String {
    let name = host.name.as_deref().unwrap_or("unknown");
    let ip = host.ip.as_deref().unwrap_or("n/a");
    if let Some(nb) = host.netbios.as_deref() {
        format!("{name} ({ip} / {nb})")
    } else {
        format!("{name} ({ip})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_host() -> Host {
        Host {
            id: 1,
            nessus_report_id: None,
            name: Some("srv".into()),
            os: None,
            mac: None,
            start: None,
            end: None,
            ip: Some("1.1.1.1".into()),
            fqdn: None,
            netbios: None,
            notes: None,
            risk_score: None,
            user_id: None,
            engagement_id: None,
        }
    }

    #[test]
    fn heading_and_label() {
        let h = sample_host();
        assert_eq!(host_heading(&h), "## srv");
        assert_eq!(host_label(&h), "srv (1.1.1.1)");
    }

    #[test]
    fn label_includes_netbios() {
        let mut h = sample_host();
        h.netbios = Some("EXAMPLE".into());
        assert_eq!(host_label(&h), "srv (1.1.1.1 / EXAMPLE)");
    }
}
