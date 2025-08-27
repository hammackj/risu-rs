use std::path::Path;

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::Error;
use crate::models::{Host, Item, Plugin};

use super::NessusReport;

/// Parse an Nmap XML report into a [`NessusReport`]. The mapping is lossy but
/// provides basic host and open port information so templates and
/// post-processing can operate on the data.
pub fn parse_file(path: &Path) -> Result<NessusReport, Error> {
    let mut reader = Reader::from_file(path)?;
    reader.trim_text(true);
    let mut buf = Vec::new();

    let mut report = NessusReport::default();
    report.version = "nmap".to_string();

    struct PendingPort {
        port: Option<i32>,
        protocol: Option<String>,
        service: Option<String>,
        state: Option<String>,
    }

    let mut current_host: Option<Host> = None;
    let mut current_port: Option<PendingPort> = None;
    let mut plugin_added = false;

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => match e.name().as_ref() {
                b"host" => current_host = Some(empty_host()),
                b"address" => {
                    if let Some(ref mut host) = current_host {
                        for a in e.attributes().flatten() {
                            if a.key.as_ref() == b"addr" {
                                host.ip = Some(a.unescape_value()?.to_string());
                            }
                        }
                    }
                }
                b"port" => {
                    let mut p = PendingPort {
                        port: None,
                        protocol: None,
                        service: None,
                        state: None,
                    };
                    for a in e.attributes().flatten() {
                        match a.key.as_ref() {
                            b"portid" => {
                                p.port = a.unescape_value().ok().and_then(|v| v.parse().ok())
                            }
                            b"protocol" => p.protocol = Some(a.unescape_value()?.to_string()),
                            _ => {}
                        }
                    }
                    current_port = Some(p);
                }
                b"state" => {
                    if let Some(ref mut p) = current_port {
                        for a in e.attributes().flatten() {
                            if a.key.as_ref() == b"state" {
                                p.state = Some(a.unescape_value()?.to_string());
                            }
                        }
                    }
                }
                b"service" => {
                    if let Some(ref mut p) = current_port {
                        for a in e.attributes().flatten() {
                            if a.key.as_ref() == b"name" {
                                p.service = Some(a.unescape_value()?.to_string());
                            }
                        }
                    }
                }
                _ => {}
            },
            Event::End(e) => match e.name().as_ref() {
                b"port" => {
                    if let Some(p) = current_port.take() {
                        if p.state.as_deref() == Some("open") {
                            if !plugin_added {
                                let mut plugin = Plugin::default();
                                plugin.plugin_id = Some(0);
                                plugin.plugin_name = Some("Open Port".to_string());
                                report.plugins.push(plugin);
                                plugin_added = true;
                            }
                            let mut item = Item::default();
                            item.plugin_id = Some(0);
                            item.port = p.port;
                            item.protocol = p.protocol;
                            item.svc_name = p.service;
                            report.items.push(item);
                        }
                    }
                }
                b"host" => {
                    if let Some(host) = current_host.take() {
                        report.hosts.push(host);
                    }
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
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
