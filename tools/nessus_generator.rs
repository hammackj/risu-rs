use std::env;
use std::io::{self, Write};

fn main() {
    let mut args = env::args().skip(1);
    let host_count: usize = args
        .next()
        .expect("host count")
        .parse()
        .expect("host count should be a number");
    let plugin_ids: Vec<String> = args.collect();

    let mut out = io::BufWriter::new(io::stdout());
    writeln!(out, "<NessusClientData_v2>").unwrap();
    for i in 0..host_count {
        writeln!(out, "  <ReportHost name=\"h{}\">", i + 1).unwrap();
        writeln!(out, "    <HostProperties></HostProperties>").unwrap();
        for pid in &plugin_ids {
            writeln!(out, "    <ReportItem pluginID=\"{}\" severity=\"0\" pluginName=\"plug{}\"></ReportItem>", pid, pid).unwrap();
        }
        writeln!(out, "  </ReportHost>").unwrap();
    }
    writeln!(out, "</NessusClientData_v2>").unwrap();
}

