use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use plotters::prelude::*;

use crate::schema::nessus_items::dsl::{
    host_id, nessus_items, rollup_finding, scanner_id as sid_col, severity,
};

/// Generate a bar chart showing the number of hosts by their highest severity level.
/// The result is saved to `dir/host_severity_counts.png` and the path is returned.
pub struct HostSeverityCountsGraph;

impl HostSeverityCountsGraph {
    fn severity_label(val: i32) -> &'static str {
        match val {
            4 => "Critical",
            3 => "High",
            2 => "Medium",
            1 => "Low",
            _ => "Info",
        }
    }

    pub fn generate(
        conn: &mut SqliteConnection,
        dir: &Path,
        scanner: Option<i32>,
    ) -> Result<PathBuf, Box<dyn Error>> {
        let mut query = nessus_items
            .select((host_id, severity))
            .filter(
                host_id
                    .is_not_null()
                    .and(severity.is_not_null())
                    .and(rollup_finding.ne(true).or(rollup_finding.is_null())),
            )
            .into_boxed();
        if let Some(sid) = scanner {
            query = query.filter(sid_col.eq(sid));
        }
        let rows: Vec<(Option<i32>, Option<i32>)> = query.load(conn)?;

        let mut host_max: HashMap<i32, i32> = HashMap::new();
        for (hid, sev) in rows.into_iter() {
            if let (Some(h), Some(s)) = (hid, sev) {
                let entry = host_max.entry(h).or_insert(s);
                if s > *entry {
                    *entry = s;
                }
            }
        }

        let mut counts: HashMap<i32, i32> = HashMap::new();
        for sev in host_max.values() {
            *counts.entry(*sev).or_insert(0) += 1;
        }

        if counts.is_empty() {
            return Err("no vulnerability data".into());
        }

        let mut data: Vec<(i32, i32)> = counts.into_iter().collect();
        data.sort_by_key(|(sev, _)| *sev);
        let labels: Vec<String> = data
            .iter()
            .map(|(sev, _)| Self::severity_label(*sev).to_string())
            .collect();
        let max_count = data.iter().map(|(_, c)| *c).max().unwrap_or(0);

        let file = dir.join("host_severity_counts.png");
        let tmp = file.clone();
        let root = BitMapBackend::new(&tmp, (800, 600)).into_drawing_area();
        root.fill(&WHITE)?;

        let mut chart = ChartBuilder::on(&root)
            .margin(20)
            .caption("Hosts by Highest Severity", ("sans-serif", 30))
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
                    labels[idx].clone()
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
}
