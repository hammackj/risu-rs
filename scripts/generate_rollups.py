import re, json, pathlib

ruby_dir = pathlib.Path('/risu-ruby/lib/risu/parsers/nessus/postprocess')
out_path = pathlib.Path('src/postprocess/rollups.rs')

skip = {'post_process.rb', 'risk_score.rb', 'root_cause.rb'}
files = sorted(f for f in ruby_dir.glob('*.rb') if f.name not in skip)

with open(out_path, 'w') as out:
    out.write('// Auto-generated from Ruby postprocess definitions\n')
    out.write('use super::{PluginEntry, PostProcess, PostProcessInfo};\n')
    out.write('use crate::parser::NessusReport;\n')
    out.write('use crate::models::{Item, Plugin};\n\n')

    out.write('fn run_rollup(report: &mut NessusReport, plugin_id: i32, plugin_name: &str, item_name: &str, description: &str, plugin_ids: &[i32]) {\n')
    out.write('    let mut found = false;\n')
    out.write('    let mut max_sev = 0;\n')
    out.write('    for item in &mut report.items {\n')
    out.write('        if let Some(pid) = item.plugin_id {\n')
    out.write('            if plugin_ids.contains(&pid) {\n')
    out.write('                found = true;\n')
    out.write('                if let Some(sev) = item.severity { if sev > max_sev { max_sev = sev; } }\n')
    out.write('                item.real_severity = item.severity;\n')
    out.write('                item.severity = Some(-1);\n')
    out.write('            }\n')
    out.write('        }\n')
    out.write('    }\n')
    out.write('    if !found { return; }\n')
    out.write('    let mut plugin = Plugin::default();\n')
    out.write('    plugin.plugin_id = Some(plugin_id);\n')
    out.write('    plugin.plugin_name = Some(plugin_name.to_string());\n')
    out.write('    plugin.family_name = Some("Risu Rollup Plugins".to_string());\n')
    out.write('    plugin.description = Some(description.to_string());\n')
    out.write('    plugin.plugin_type = Some("Rollup".to_string());\n')
    out.write('    plugin.rollup = Some(true);\n')
    out.write('    report.plugins.push(plugin);\n')
    out.write('    let mut item = Item::default();\n')
    out.write('    item.plugin_id = Some(plugin_id);\n')
    out.write('    item.plugin_name = Some(item_name.to_string());\n')
    out.write('    item.severity = Some(max_sev);\n')
    out.write('    report.items.push(item);\n')
    out.write('}\n\n')

    order = 1000
    for f in files:
        text = f.read_text()
        def extract(pattern, flags=0):
            m = re.search(pattern, text, flags)
            return m.group(1) if m else ''
        desc = extract(r":description\s*=>\s*\"([^\"]+)\"")
        plugin_id = extract(r":plugin_id\s*=>\s*([-0-9]+)")
        plugin_name = extract(r":plugin_name\s*=>\s*\"([^\"]+)\"")
        item_name = extract(r":item_name\s*=>\s*\"([^\"]+)\"")
        ids_block = extract(r":plugin_ids\s*=>\s*\[(.*?)\]", re.S)
        ids = []
        for line in ids_block.splitlines():
            line = line.split('#')[0]
            m = re.search(r'-?\d+', line)
            if m:
                ids.append(m.group(0))
        struct_name = ''.join(part.capitalize() for part in re.split(r'[^0-9A-Za-z]', f.stem) if part)
        if struct_name and struct_name[0].isdigit():
            struct_name = 'Plugin' + struct_name
        const_base = re.sub(r'[^0-9A-Za-z]', '_', f.stem).upper()
        if const_base and const_base[0].isdigit():
            const_base = 'P' + const_base
        const_name = 'PLUGIN_IDS_' + const_base
        out.write(f'struct {struct_name};\n\n')
        out.write(f'impl PostProcess for {struct_name} {{\n')
        out.write('    fn info(&self) -> PostProcessInfo {\n')
        out.write(f'        PostProcessInfo {{ name: {json.dumps(f.stem)}, order: {order} }}\n')
        out.write('    }\n')
        out.write('    fn run(&self, report: &mut NessusReport) {\n')
        out.write(f'        run_rollup(report, {plugin_id}, {json.dumps(plugin_name)}, {json.dumps(item_name)}, {json.dumps(desc)}, {const_name});\n')
        out.write('    }\n')
        out.write('}\n\n')
        out.write(f'inventory::submit! {{\n    PluginEntry {{ plugin: &{struct_name} }}\n}}\n\n')
        out.write(f'const {const_name}: &[i32] = &[{", ".join(ids)}];\n\n')
        order += 1
