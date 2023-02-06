use std::process;

fn main() {
    if let Err(e) = bitwrought::run() {
        eprintln!("Application error: {e}");
        process::exit(1);
    }
}
