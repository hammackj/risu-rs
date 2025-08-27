use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use plotters::prelude::*;

use crate::parser::NessusReport;

pub mod top_vuln;
pub mod windows_os;
pub mod malware;
pub mod os_distribution;
pub mod vulns_by_service;
pub mod vuln_category;
pub mod host_severity_counts;

pub use top_vuln::TopVulnGraph;
pub use windows_os::WindowsOsGraph;
pub use malware::malware;
pub use os_distribution::{count_os, os_distribution, OsDistributionGraph};
pub use vulns_by_service::VulnsByServiceGraph;
pub use vuln_category::VulnCategoryGraph;
pub use host_severity_counts::HostSeverityCountsGraph;

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
