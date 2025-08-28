use regex::Regex;
use std::fs;
use std::path::Path;

// Simple utility to extract rollup definitions from src/postprocess/rollups.rs
// and write them to a TOML file compatible with the runtime TOML loader.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let src_path = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("src/postprocess/rollups.rs");
    let out_path = args.get(2).map(|s| s.as_str()).unwrap_or("rollups.toml");

    let text = fs::read_to_string(src_path)?;

    // Capture blocks: run_rollup(report, ...);
    let call_block_re = Regex::new(r#"run_rollup\s*\(\s*report\s*,(?s)(.*?)\);"#)?;
    // Inside args: id, "name", "item", "desc", CONST
    let args_re = Regex::new(
        r#"^\s*([-]?\d+)\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*([A-Z0-9_]+)\s*,?\s*$"#,
    )?;
    // Capture const arrays: const CONST_NAME: &[i32] = &[ ... ];
    let const_re = Regex::new(r#"(?s)const\s+([A-Z0-9_]+):\s*&\[i32\]\s*=\s*&\[(.*?)\];"#)?;
    // Match all integer IDs within the const array body
    let num_re = Regex::new(r#"-?\d+"#)?;

    // Build map of CONST_NAME -> Vec<i32>
    let mut id_map = std::collections::HashMap::new();
    for cap in const_re.captures_iter(&text) {
        let name = cap.get(1).unwrap().as_str().to_string();
        let body = cap.get(2).unwrap().as_str();
        let ids: Vec<i32> = num_re
            .find_iter(body)
            .filter_map(|m| m.as_str().parse::<i32>().ok())
            .collect();
        id_map.insert(name, ids);
    }

    let mut out = String::new();
    for cap in call_block_re.captures_iter(&text) {
        let inner = cap.get(1).unwrap().as_str().trim();
        let args_cap = match args_re.captures(inner) {
            Some(c) => c,
            None => continue,
        };
        let plugin_id: i32 = args_cap.get(1).unwrap().as_str().parse()?;
        let plugin_name = args_cap.get(2).unwrap().as_str();
        let item_name = args_cap.get(3).unwrap().as_str();
        let description = args_cap.get(4).unwrap().as_str();
        let const_name = args_cap.get(5).unwrap().as_str();

        let ids = id_map.get(const_name).cloned().unwrap_or_default();
        out.push_str("[[rollup]]\n");
        out.push_str(&format!("plugin_id = {}\n", plugin_id));
        out.push_str(&format!("plugin_name = \"{}\"\n", plugin_name.replace('"', "\\\"")));
        out.push_str(&format!("item_name = \"{}\"\n", item_name.replace('"', "\\\"")));
        out.push_str(&format!("description = \"{}\"\n", description.replace('"', "\\\"")));
        out.push_str("plugin_ids = [");
        for (i, id) in ids.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&id.to_string());
        }
        out.push_str("]\n\n");
    }

    let count = call_block_re.captures_iter(&text).count();
    fs::write(out_path, out)?;
    println!(
        "Wrote rollups TOML with {} entries to {}",
        count,
        Path::new(out_path).display()
    );
    Ok(())
}
