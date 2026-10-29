//! Compiles the Slint UI. The icon resource (id 1) is embedded by the single
//! `unfilter` binary's build script, not here — this is a library crate, and
//! resources only link when attached to the final executable.
fn main() {
    slint_build::compile("ui/app.slint").expect("compile ui/app.slint");
}
