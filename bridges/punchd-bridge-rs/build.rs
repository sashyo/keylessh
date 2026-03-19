fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("favicon.ico");
        res.set("ProductName", "Punchd Gateway");
        res.set("FileDescription", "Punchd Gateway");
        res.compile().expect("Failed to compile Windows resources");
    }
}
