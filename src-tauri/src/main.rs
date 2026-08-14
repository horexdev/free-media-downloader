#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Some(status) = fmd_app_lib::maybe_run_update_helper() {
        std::process::exit(status);
    }
    if let Some(status) = fmd_app_lib::maybe_run_smoke_check() {
        std::process::exit(status);
    }
    fmd_app_lib::run();
}
