//! Embeds the application and tray icons into the single executable. The icon
//! ids (1 = app, 101–105 = tray states) must match `uf-tray`'s `mod icon` and
//! the `LoadImageW`/`WM_SETICON` calls in `uf-ui`/`uf-tray`, which resolve them
//! from this binary's module handle at runtime. Also embeds WinDivert when
//! `assets/windivert` holds it.
fn main() {
    // Embed the signed WinDivert files (scripts/fetch-windivert.ps1) when they
    // are present, so the one exe runs with nothing beside it.
    println!("cargo::rustc-check-cfg=cfg(embedded_windivert)");
    println!("cargo:rerun-if-changed=../../assets/windivert");
    let dir = std::path::Path::new("../../assets/windivert");
    if dir.join("WinDivert.dll").is_file() && dir.join("WinDivert64.sys").is_file() {
        println!("cargo:rustc-cfg=embedded_windivert");
    } else {
        println!(
            "cargo:warning=assets/windivert missing: run scripts/fetch-windivert.ps1 to embed WinDivert"
        );
    }

    println!("cargo:rerun-if-changed=unfilter.rc");
    println!("cargo:rerun-if-changed=../../assets/icons");
    if let Err(e) = embed_resource::compile("unfilter.rc", embed_resource::NONE).manifest_optional()
    {
        panic!("embedding unfilter.rc failed: {e}");
    }
}
