use super::{PluginEntry, PostProcess, PostProcessInfo};
use crate::parser::NessusReport;

struct NormalizePluginNames;

impl PostProcess for NormalizePluginNames {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "normalize_plugin_names",
            order: 30,
        }
    }

    fn run(&self, report: &mut NessusReport) {
        for plugin in &mut report.plugins {
            if let Some(ref mut name) = plugin.plugin_name {
                for s in STRINGS_TO_SANITIZE {
                    *name = name.replace(s, "").trim().to_string();
                }
            }
        }
    }
}

inventory::submit! {
    PluginEntry { plugin: &NormalizePluginNames }
}

static STRINGS_TO_SANITIZE: &[&str] = &[
    "(ERRATICGOPHER)",
    "(SWEET32)",
    "(POODLE)",
    "(BEAST)",
    "(remote check)",
    "(FREAK)",
    "(Bar Mitzvah)",
    "(Logjam)",
    "(uncredentialed check)",
    "(EXPLODINGCAN)",
    "(Foreshadow)",
    "(MSXML)",
];
