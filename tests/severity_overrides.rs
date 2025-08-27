use std::collections::HashMap;

use risu_rs::models::Item;
use risu_rs::parser::{apply_severity_overrides, NessusReport};

#[test]
fn overrides_update_item_severity() {
    let mut item = Item::default();
    item.plugin_id = Some(1234);
    item.severity = Some(4);
    let mut report = NessusReport {
        items: vec![item],
        ..NessusReport::default()
    };
    let mut overrides = HashMap::new();
    overrides.insert(1234, 1);
    apply_severity_overrides(&mut report, &overrides);
    assert_eq!(report.items[0].severity, Some(1));
}
