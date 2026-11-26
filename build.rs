fn main() {
    println!("cargo:rerun-if-env-changed=TARGET");
    if let Ok(target) = std::env::var("TARGET") {
        println!("cargo:rustc-env=RBW_TARGET={target}");
    }
}
