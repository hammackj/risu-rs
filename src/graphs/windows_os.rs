use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use plotters::prelude::*;

use crate::schema::nessus_hosts::dsl::{nessus_hosts, os};

/// Generate a pie chart showing the distribution of Windows operating systems.
/// The result is saved to `dir/windows_os.png` and the path is returned.
pub struct WindowsOsGraph;

impl WindowsOsGraph {
    /// Query the database for host operating system information and render a pie chart.
    pub fn generate(conn: &mut SqliteConnection, dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
        let results: Vec<Option<String>> = nessus_hosts
            .select(os)
            .filter(os.like("Windows%"))
            .load(conn)?;

        let mut counts: HashMap<String, usize> = HashMap::new();
        for name in results.into_iter().flatten() {
            *counts.entry(name).or_insert(0) += 1;
        }

        if counts.is_empty() {
            return Err("no host data".into());
        }

        let file = dir.join("windows_os.png");
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

