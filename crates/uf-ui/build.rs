fn main() {
    slint_build::compile("ui/app.slint").expect("compile ui/app.slint");
    println!("cargo:rerun-if-changed=uf-ui.rc");
    println!("cargo:rerun-if-changed=../../assets/icons/unfilter.ico");
    // Icon resource id 1: shown by Explorer/taskbar and loaded for WM_SETICON.
    if let Err(e) = embed_resource::compile("uf-ui.rc", embed_resource::NONE).manifest_optional() {
        panic!("embedding uf-ui.rc failed: {e}");
    }
}
