//! Interfaz WebAssembly que usa el gateway en Go.
//!
//! 1. El host reserva memoria con `aegis_alloc(len)` y escribe la petición JSON.
//! 2. Llama a `aegis_scan(ptr, len)`, que devuelve `(ptr << 32) | len` de la
//!    respuesta JSON.
//! 3. Libera ambos bloques con `aegis_free(ptr, len)`.

use std::alloc::{Layout, alloc, dealloc};

use crate::{ScanRequest, scan, warm};

fn layout(len: u32) -> Layout {
    Layout::from_size_align(len.max(1) as usize, 1).expect("layout")
}

#[unsafe(no_mangle)]
pub extern "C" fn aegis_alloc(len: u32) -> *mut u8 {
    unsafe { alloc(layout(len)) }
}

/// # Safety
/// `ptr` debe venir de `aegis_alloc` (o de `aegis_scan`) con el mismo `len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aegis_free(ptr: *mut u8, len: u32) {
    if !ptr.is_null() {
        unsafe { dealloc(ptr, layout(len)) }
    }
}

/// Compila las reglas por adelantado.
#[unsafe(no_mangle)]
pub extern "C" fn aegis_init() {
    warm();
}

/// # Safety
/// `ptr..ptr+len` debe ser memoria válida escrita por el host.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aegis_scan(ptr: *const u8, len: u32) -> u64 {
    let input: &[u8] = if len == 0 || ptr.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len as usize) }
    };

    let output = match serde_json::from_slice::<ScanRequest>(input) {
        Ok(req) => serde_json::to_vec(&scan(&req)),
        Err(e) => serde_json::to_vec(&serde_json::json!({ "error": e.to_string() })),
    }
    .unwrap_or_else(|_| br#"{"error":"serialization"}"#.to_vec());

    let out_len = output.len() as u32;
    let out_ptr = aegis_alloc(out_len);
    unsafe { std::ptr::copy_nonoverlapping(output.as_ptr(), out_ptr, output.len()) };
    ((out_ptr as u64) << 32) | out_len as u64
}
