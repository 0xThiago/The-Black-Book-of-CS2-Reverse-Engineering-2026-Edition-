# 💉 DLL Injection

📅 Criado em: 2026-02-17
🔗 Tags: #conceito #injection #process-manipulation #evasion

## 📌 Definição

**DLL Injection** é a técnica de forçar um processo alvo a carregar e executar código malicioso contido em uma Dynamic Link Library (DLL). É um dos métodos mais fundamentais de process manipulation, permitindo que cheats executem no contexto do jogo sem modificar o binário original.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[Manual_Mapping]]
- [[Reflective_DLL_Injection]]
- [[Process_Hollowing]]
- [[APC_Injection]]
- [[Code_Injection]]

## 📚 Métodos de Injeção (2026)

### 1. Classic LoadLibrary Injection

```rust
use windows::Win32::System::{LibraryLoader::*, Memory::*, Threading::*, Diagnostics::Debug::*};
use windows::core::*;

/// Injeta DLL via CreateRemoteThread + LoadLibraryA
pub unsafe fn classic_dll_injection(
    target_pid: u32,
    dll_path: &str,
) -> Result<(), String> {
    // 1. Abrir processo alvo
    let process_handle = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | 
        PROCESS_VM_WRITE | PROCESS_VM_READ,
        false,
        target_pid,
    ).map_err(|e| format!("Failed to open process: {}", e))?;
    
    // 2. Alocar memória no processo remoto para o caminho da DLL
    let dll_path_cstr = std::ffi::CString::new(dll_path).unwrap();
    let dll_path_size = dll_path_cstr.as_bytes_with_nul().len();
    
    let remote_buffer = VirtualAllocEx(
        process_handle,
        None,
        dll_path_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    
    if remote_buffer.is_null() {
        return Err("VirtualAllocEx failed".to_string());
    }
    
    // 3. Escrever caminho da DLL na memória remota
    let mut bytes_written = 0;
    WriteProcessMemory(
        process_handle,
        remote_buffer,
        dll_path_cstr.as_ptr() as *const _,
        dll_path_size,
        Some(&mut bytes_written),
    ).map_err(|e| format!("WriteProcessMemory failed: {}", e))?;
    
    // 4. Obter endereço de LoadLibraryA
    let kernel32 = GetModuleHandleA(s!("kernel32.dll"))
        .map_err(|e| format!("GetModuleHandle failed: {}", e))?;
    
    let loadlibrary_addr = GetProcAddress(kernel32, s!("LoadLibraryA"))
        .ok_or("GetProcAddress failed")?;
    
    // 5. Criar thread remota que executa LoadLibraryA(dll_path)
    let thread_handle = CreateRemoteThread(
        process_handle,
        None,
        0,
        Some(std::mem::transmute(loadlibrary_addr)),
        Some(remote_buffer),
        0,
        None,
    ).map_err(|e| format!("CreateRemoteThread failed: {}", e))?;
    
    // 6. Esperar thread completar
    WaitForSingleObject(thread_handle, 5000);
    
    // 7. Cleanup
    VirtualFreeEx(process_handle, remote_buffer, 0, MEM_RELEASE);
    CloseHandle(thread_handle);
    CloseHandle(process_handle);
    
    Ok(())
}
```

**Análise Rust Sentinel**:

> **CAMADA 1: SINTAXE**  
> Utilizamos WinAPI via `windows-rs` para manipular processo remoto. CreateRemoteThread força execução de LoadLibraryA no contexto do alvo.
> 
> **CAMADA 2: MEMÓRIA**  
> `VirtualAllocEx` aloca páginas RW no address space do processo alvo. O caminho da DLL (stack local) é copiado para a heap remota do processo via `WriteProcessMemory`.
> 
> **CAMADA 3: SEGURANÇA & OWNERSHIP**  
> Rust força que gerenciemos os handles via RAII. `CloseHandle` no final garante que não vazamos recursos. O uso de `Result<>` obriga tratamento de erros.

### 2. Manual Mapping (Stealth)

```rust
/// Injeta DLL sem chamar LoadLibrary (evita detecção)
pub unsafe fn manual_map_injection(
    target_pid: u32,
    dll_bytes: &[u8],
) -> Result<(), String> {
    let process_handle = OpenProcess(
        PROCESS_ALL_ACCESS,
        false,
        target_pid,
    )?;
    
    // 1. Parsear PE headers
    let pe_parser = PEParser::new(dll_bytes)?;
    let image_size = pe_parser.get_image_size();
    
    // 2. Alocar memória para a imagem completa
    let remote_image = VirtualAllocEx(
        process_handle,
        None,
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE, // Mudaremos depois
    );
    
    if remote_image.is_null() {
        return Err("Failed to allocate remote image".to_string());
    }
    
    // 3. Copiar headers
    WriteProcessMemory(
        process_handle,
        remote_image,
        dll_bytes.as_ptr() as *const _,
        pe_parser.headers_size(),
        None,
    )?;
    
    // 4. Copiar seções (ajustando RVAs)
    for section in pe_parser.get_sections() {
        let section_data = &dll_bytes[section.pointer_to_raw_data..][..section.size_of_raw_data];
        let dest_addr = (remote_image as usize + section.virtual_address) as *mut _;
        
        WriteProcessMemory(
            process_handle,
            dest_addr,
            section_data.as_ptr() as *const _,
            section_data.len(),
            None,
        )?;
    }
    
    // 5. Resolver imports (crucial!)
    resolve_imports(process_handle, remote_image, &pe_parser)?;
    
    // 6. Aplicar relocations
    apply_relocations(process_handle, remote_image, &pe_parser)?;
    
    // 7. Ajustar proteções de memória
    for section in pe_parser.get_sections() {
        let protection = match section.characteristics {
            x if x & 0x20000000 != 0 => PAGE_EXECUTE_READ, // Executable
            x if x & 0x80000000 != 0 => PAGE_READWRITE,     // Writable
            _ => PAGE_READONLY,
        };
        
        let section_addr = (remote_image as usize + section.virtual_address) as *mut _;
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            process_handle,
            section_addr,
            section.virtual_size as usize,
            protection,
            &mut old_protect,
        )?;
    }
    
    // 8. Executar DllMain via thread remota
    let entry_point = (remote_image as usize + pe_parser.get_entry_point()) as *mut _;
    
    let thread = CreateRemoteThread(
        process_handle,
        None,
        0,
        Some(std::mem::transmute(entry_point)),
        Some(remote_image), // DLL_PROCESS_ATTACH
        0,
        None,
    )?;
    
    WaitForSingleObject(thread, u32::MAX);
    CloseHandle(thread);
    CloseHandle(process_handle);
    
    Ok(())
}

struct PEParser {
    // Simplified PE parser
}
```

### 3. Reflective DLL Injection

```rust
/// DLL que carrega a si mesma na memória sem LoadLibrary
/// (Código roda dentro da DLL, não no injector)
#[no_mangle]
pub unsafe extern "system" fn ReflectiveLoader(param: *mut std::ffi::c_void) -> u32 {
    // 1. Encontrar própria base via hash do PEB
    let peb = get_peb();
    let own_base = find_own_base_address(peb);
    
    // 2. Parsear próprios headers
    let dos_header = own_base as *const IMAGE_DOS_HEADER;
    let nt_headers = (own_base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    
    // 3. Alocar nova região para re-mapear
    let image_size = (*nt_headers).OptionalHeader.SizeOfImage;
    let new_base = VirtualAlloc(
        None,
        image_size as usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    
    // 4. Copiar headers e seções
    std::ptr::copy_nonoverlapping(
        own_base as *const u8,
        new_base as *mut u8,
        (*nt_headers).OptionalHeader.SizeOfHeaders as usize,
    );
    
    // ... (seções, relocations, imports)
    
    // 5. Chamar DllMain real
    let dll_main_addr = (new_base as usize + (*nt_headers).OptionalHeader.AddressOfEntryPoint as usize) as *const ();
    let dll_main: extern "system" fn(HINSTANCE, u32, *mut std::ffi::c_void) -> bool = std::mem::transmute(dll_main_addr);
    dll_main(HINSTANCE(new_base as isize), 1 /* DLL_PROCESS_ATTACH */, param as *mut _);
    
    0
}
```

## 🎯 Aplicação em CS2 (2026)

### Caso: Injetar ESP Overlay

```rust
pub fn inject_esp_dll(cs2_pid: u32) -> Result<(), String> {
    let dll_path = r"C:\cheats\cs2_esp.dll";
    
    // Método clássico (detectável)
    // unsafe { classic_dll_injection(cs2_pid, dll_path) }
    
    // Método stealth (manual mapping)
    let dll_bytes = std::fs::read(dll_path)
        .map_err(|e| format!("Failed to read DLL: {}", e))?;
    
    unsafe { manual_map_injection(cs2_pid, &dll_bytes) }
}
```

## ⚠️ Detecção e Contramedidas (2026)

### Como Anti-Cheats Detectam

```
1. Module enumeration (LoadLibrary deixa rastro)
   └─ Solução: Manual mapping

2. Memory scanning (código na memória)
   └─ Solução: Encrypt DLL em memória + decrypt on-demand

3. Thread creation monitoring
   └─ Solução: Thread hijacking ao invés de CreateRemoteThread

4. Import Address Table (IAT) hooks
   └─ Solução: Resolver imports via hash, não nome

5. Assinaturas de injectors conhecidos
   └─ Solução: Polymorphic injector
```

### Técnicas Avançadas (2026)

**Thread Hijacking**:
```rust
// Ao invés de CreateRemoteThread, sequestrar thread existente
unsafe fn thread_hijack_injection(target_pid: u32) -> Result<(), String> {
    // 1. Enumerar threads do processo
    // 2. Suspender thread
    // 3. Modificar RIP para apontar para shellcode
    // 4. Shellcode carrega DLL
    // 5. Restaurar RIP original
    // 6. Resumir thread
    Ok(())
}
```

## 📊 Comparação de Métodos

| Método | Stealth | Complexidade | Detecção 2026 |
|--------|---------|--------------|---------------|
| **LoadLibrary** | 🔴 Baixo | 🟢 Simples | 🔴 Alta |
| **Manual Mapping** | 🟡 Médio | 🟡 Médio | 🟡 Média |
| **Reflective** | 🟢 Alto | 🔴 Complexo | 🟢 Baixa |
| **Thread Hijack** | 🟢 Alto | 🔴 Muito complexo | 🟢 Baixa |

## 📖 Ver Também
- [[Manual_Mapping]]
- [[Reflective_DLL_Injection]]
- [[Process_Hollowing]]
- [[APC_Injection]]
- [[Code_Injection]]

---
<p align="center">REDFLAG © 2026</p>
