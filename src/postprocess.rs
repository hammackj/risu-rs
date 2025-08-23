/// Perform post-processing on parsed data
pub fn process(data: &str) {
    if data.is_empty() {
        println!("No data to process");
    } else {
        println!("Post-processing {} bytes of data", data.len());
    }
}

