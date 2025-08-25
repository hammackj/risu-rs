use std::io::BufRead;

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::Error;
use crate::models::Host;
use crate::parser::NessusReport;

/// Parse a `NeXposeSimpleXML` document from the provided reader.
pub fn parse<B: BufRead>(reader: &mut Reader<B>) -> Result<NessusReport, Error> {
    let mut buf = Vec::new();
    let mut report = NessusReport::default();
    report.version = "nexpose-simple-xml".to_string();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => match e.name().as_ref() {
                b"node" => {
                    let mut host = empty_host();
                    for a in e.attributes().flatten() {
                        match a.key.as_ref() {
                            b"address" => host.ip = Some(a.unescape_value()?.to_string()),
                            b"name" => host.name = Some(a.unescape_value()?.to_string()),
                            _ => {}
                        }
                    }
                    report.hosts.push(host);
                }
                _ => {}
            },
            Event::End(e) => {
                if e.name().as_ref() == b"NeXposeSimpleXML" {
                    break;
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    // IP fix-up similar to `fix_ips`
    for host in &mut report.hosts {
        if host.ip.is_none() {
            if let Some(name) = host.name.clone() {
                host.ip = Some(name);
            }
        }
    }

    Ok(report)
}

fn empty_host() -> Host {
    Host {
        id: 0,
        nessus_report_id: None,
        name: None,
        os: None,
        mac: None,
        start: None,
        end: None,
        ip: None,
        fqdn: None,
        netbios: None,
        notes: None,
        risk_score: None,
        user_id: None,
        engagement_id: None,
    }
}
