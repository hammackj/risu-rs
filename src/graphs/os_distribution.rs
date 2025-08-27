use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use plotters::prelude::*;

use crate::parser::NessusReport;
use crate::schema::nessus_hosts::dsl::{nessus_hosts, os as host_os, scanner_id as host_scanner_id};

use super::windows_os::normalize_windows_os;

/// Count operating systems in a [`NessusReport`].
pub fn count_os(report: &NessusReport) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for host in &report.hosts {
        let os = host
            .os
            .clone()
            .unwrap_or_else(|| "Unknown".to_string());
        let os = normalize_windows_os(&os).to_string();
        *counts.entry(os).or_default() += 1;
    }
    counts
}

/// Generate an OS distribution graph from a [`NessusReport`].
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

/// Generate an OS distribution graph from the database.
///
/// The resulting PNG is saved to `dir/os_distribution.png` and the path is
/// returned.
pub struct OsDistributionGraph;

impl OsDistributionGraph {
    fn count(results: Vec<Option<String>>) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for name in results.into_iter().flatten() {
            let normalized = normalize_windows_os(&name).to_string();
            *counts.entry(normalized).or_insert(0) += 1;
        }
        counts
    }

    pub fn generate(
        conn: &mut SqliteConnection,
        dir: &Path,
        scanner: Option<i32>,
    ) -> Result<PathBuf, Box<dyn Error>> {
        let mut query = nessus_hosts.select(host_os).into_boxed();
        if let Some(sid) = scanner {
            query = query.filter(host_scanner_id.eq(sid));
        }
        let results: Vec<Option<String>> = query.load(conn)?;

        let counts = Self::count(results);
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
        for (i, (name, count)) in counts.into_iter().enumerate() {
            sizes.push(count as f64);
            let (r, g, b) = Palette99::pick(i).rgb();
            colors.push(RGBColor(r, g, b));
            labels.push(name);
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
