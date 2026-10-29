//! Embeds the application and tray icons into the single executable. The icon
//! ids (1 = app, 101–105 = tray states) must match `uf-tray`'s `mod icon` and
//! the `LoadImageW`/`WM_SETICON` calls in `uf-ui`/`uf-tray`, which resolve them
//! from this binary's module handle at runtime.
fn main() {
    println!("cargo:rerun-if-changed=unfilter.rc");
    println!("cargo:rerun-if-changed=../../assets/icons");
    if let Err(e) = embed_resource::compile("unfilter.rc", embed_resource::NONE).manifest_optional()
    {
        panic!("embedding unfilter.rc failed: {e}");
    }
}
