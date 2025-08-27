use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use plotters::prelude::*;

use crate::schema::nessus_items::dsl::{nessus_items, plugin_name, rollup_finding};

/// Generate a bar chart showing the most common vulnerabilities.
/// The result is saved to `dir/top_vulnerabilities.png` and the path is returned.
pub struct TopVulnGraph;

impl TopVulnGraph {
    /// Query the database for the top `limit` vulnerability names and render a bar chart.
    pub fn generate(
        conn: &mut SqliteConnection,
        dir: &Path,
        limit: usize,
        scanner: Option<i32>,
    ) -> Result<PathBuf, Box<dyn Error>> {
        let mut query = nessus_items
            .select(plugin_name)
            .filter(
                plugin_name
                    .is_not_null()
                    .and(rollup_finding.ne(true).or(rollup_finding.is_null())),
            )
            .into_boxed();
        if let Some(sid) = scanner {
            use crate::schema::nessus_items::dsl::scanner_id as sid_col;
            query = query.filter(sid_col.eq(sid));
        }
        let names: Vec<Option<String>> = query.load(conn)?;

        let mut counts: HashMap<String, i32> = HashMap::new();
        for name in names.into_iter().flatten() {
            *counts.entry(name).or_insert(0) += 1;
        }

        let mut data: Vec<(String, i32)> = counts.into_iter().collect();
        data.sort_by(|a, b| b.1.cmp(&a.1));
        data.truncate(limit);

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
}
