fn main() {
    println!("cargo:rerun-if-changed=uf-tray.rc");
    println!("cargo:rerun-if-changed=../../assets/icons");
    if let Err(e) = embed_resource::compile("uf-tray.rc", embed_resource::NONE).manifest_optional()
    {
        panic!("embedding uf-tray.rc failed: {e}");
    }
}
