/// Generate a configuration file optionally based on a template
pub fn generate(template: Option<&str>) {
    if let Some(t) = template {
        println!("Generating config from template: {}", t);
    } else {
        println!("Generating default configuration");
    }
}

