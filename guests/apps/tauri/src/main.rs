//! One window showing `dist/index.html`: the application tests check that
//! it is drawn, magenta with "fwe" in green.

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("the app runs");
}
