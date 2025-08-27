use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use plotters::prelude::*;

use crate::parser::NessusReport;
use windows_os::normalize_windows_os;

pub mod top_vuln;
pub mod windows_os;
pub mod malware;

pub use top_vuln::TopVulnGraph;
pub use windows_os::WindowsOsGraph;
pub use malware::malware;

/// Generate a pie chart showing operating system distribution among hosts.
/// Returns the path to the generated PNG file.
pub(crate) fn count_os(report: &NessusReport) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for host in &report.hosts {
        let os = host.os.clone().unwrap_or_else(|| "Unknown".to_string());
        let os = normalize_windows_os(&os).to_string();
        *counts.entry(os).or_default() += 1;
    }
    counts
}

pub fn os_distribution(report: &NessusReport, dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let counts = count_os(report);

    if counts.is_empty() {
        return Err("no host data".into());
    }

    let file = dir.join("os_distribution.png");
    let tmp = file.clone();
    let root = BitMapBackend::new(&tmp, (640, 480)).into_drawing_area();
    root.fill(&WHITE)?;

    let dims = root.dim_in_pixel();
    let center = (dims.0 as i32 / 2, dims.1 as i32 / 2);
    let radius = (dims.0.min(dims.1) as f64) * 0.4;

    let mut sizes = Vec::new();
    let mut colors = Vec::new();
    let mut labels = Vec::new();
    for (i, (os, count)) in counts.into_iter().enumerate() {
        sizes.push(count as f64);
        let (r, g, b) = Palette99::pick(i).rgb();
        colors.push(RGBColor(r, g, b));
        labels.push(os);
    }
    let label_refs: Vec<&str> = labels.iter().map(|s| s.as_str()).collect();

    let mut pie = Pie::new(&center, &radius, &sizes, &colors, &label_refs);
    pie.label_style(("sans-serif", 15).into_font());
    pie.percentages(("sans-serif", 12).into_font());
    root.draw(&pie)?;
    root.present()?;
    drop(root);
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Host;

    fn host(os: &str) -> Host {
        Host {
            id: 0,
            nessus_report_id: None,
            name: None,
            os: Some(os.to_string()),
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
            scanner_id: None,
        }
    }

    #[test]
    fn count_os_normalizes_windows_variants() {
        let report = NessusReport {
            hosts: vec![
                host("Windows 2000"),
                host("Microsoft Windows 2000 SP4"),
                host("Windows XP"),
                host("Microsoft Windows XP Professional"),
            ],
            ..NessusReport::default()
        };
        let counts = count_os(&report);
        assert_eq!(counts.get("Windows 2000"), Some(&2));
        assert_eq!(counts.get("Windows XP"), Some(&2));
    }
}

/// Generate a bar chart of the top `n` vulnerabilities by occurrence.
/// Returns the path to the generated PNG file.
pub fn top_vulnerabilities(
    report: &NessusReport,
    dir: &Path,
    n: usize,
) -> Result<PathBuf, Box<dyn Error>> {
    let mut counts: HashMap<String, i32> = HashMap::new();
    for item in &report.items {
        if let Some(name) = &item.plugin_name {
            *counts.entry(name.clone()).or_default() += 1;
        }
    }

    let mut data: Vec<(String, i32)> = counts.into_iter().collect();
    data.sort_by(|a, b| b.1.cmp(&a.1));
    data.truncate(n);

    if data.is_empty() {
        return Err("no vulnerability data".into());
    }

    let max_count = data.iter().map(|(_, c)| *c).max().unwrap_or(0);
    let labels: Vec<String> = data.iter().map(|(n, _)| n.clone()).collect();

    let file = dir.join("top_vulnerabilities.png");
    let tmp = file.clone();
    let root = BitMapBackend::new(&tmp, (1024, 768)).into_drawing_area();
    root.fill(&WHITE)?;

    let mut chart = ChartBuilder::on(&root)
        .margin(20)
        .caption("Top Vulnerabilities", ("sans-serif", 30))
        .x_label_area_size(40)
        .y_label_area_size(40)
        .build_cartesian_2d(0..data.len() as i32, 0..(max_count + 1))?;

    chart
        .configure_mesh()
        .disable_mesh()
        .x_labels(labels.len())
        .x_label_formatter(&|x| {
            let idx = *x as usize;
            if idx < labels.len() {
                let name = &labels[idx];
                if name.len() > 10 {
                    format!("{}…", &name[..10])
                } else {
                    name.clone()
                }
            } else {
                String::new()
            }
        })
        .draw()?;

    chart.draw_series(data.iter().enumerate().map(|(i, (_, c))| {
        Rectangle::new(
            [(i as i32, 0), (i as i32 + 1, *c)],
            Palette99::pick(i).filled(),
        )
    }))?;

    root.present()?;
    drop(root);
    Ok(file)
}
