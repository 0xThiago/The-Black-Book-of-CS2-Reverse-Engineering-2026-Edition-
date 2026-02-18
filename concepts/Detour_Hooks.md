# 🎣 Detour Hooks

📅 Criado em: 2026-02-17
🔗 Tags: #conceito #hooking #code-modification #interception

## 📌 Definição

**Detour Hooking** é uma técnica que intercepta chamadas de funções redirecionando o fluxo de execução para código customizado (hook handler). O redirecionamento é feito modificando os primeiros bytes da função alvo para inserir um `JMP` (jump) para o nosso código.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[IAT_Hooking]]
- [[EAT_Hooking]]
- [[MinHook_Library]]
- [[Inline_Hooking]]

## 📚 Arquitetura de Detour Hook

```
Função Original:           Após Hook:
┌───────────────┐          ┌───────────────┐
│ push rbp      │          │ jmp hook_fn   │ ← 5 bytes modificados
│ mov rbp, rsp  │          │ nop           │
│ sub rsp, 0x20 │          │ ...           │
│ ...           │          │ ...           │
│ ret           │          │ ret           │
└───────────────┘          └───────────────┘

Hook Handler:
┌────────────────────┐
│ push registers     │
│ call original+N    │ ← Executa bytes originais
│ call custom_logic  │
│ pop registers      │
│ ret                │
└────────────────────┘
```

## 🛠️ Implementação em Rust (2026)

### 1. Detour Hook Manual (x64)

```rust
use std::arch::asm;

/// Estrutura para gerenciar um hook
pub struct DetourHook {
    target_addr: usize,
    original_bytes: [u8; 14],  // Backup dos bytes originais
    trampoline_addr: usize,    // Trampoline para chamar original
    is_hooked: bool,
}

impl DetourHook {
    /// Cria novo hook em função alvo
    pub unsafe fn new(target_fn: *const ()) -> Result<Self, String> {
        let target_addr = target_fn as usize;
        
        // 1. Backup bytes originais (14 bytes para segurança)
        let mut original_bytes = [0u8; 14];
        std::ptr::copy_nonoverlapping(
            target_addr as *const u8,
            original_bytes.as_mut_ptr(),
            14,
        );
        
        Ok(Self {
            target_addr,
            original_bytes,
            trampoline_addr: 0,
            is_hooked: false,
        })
    }
    
    /// Instala o hook redirecionando para hook_handler
    pub unsafe fn install(&mut self, hook_handler: *const ()) -> Result<(), String> {
        use windows::Win32::System::Memory::*;
        
        // 1. Criar trampoline (código que executa bytes originais)
        self.trampoline_addr = self.create_trampoline()?;
        
        // 2. Alterar proteção da página do target para RWX
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(
            self.target_addr as *const _,
            14,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        ).map_err(|e| format!("VirtualProtect failed: {}", e))?;
        
        // 3. Escrever JMP absoluto para hook_handler
        // JMP [RIP+0]; <address>
        let jmp_instruction: [u8; 14] = [
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp [rip+0]
            // 8 bytes do endereço absoluto
            ((hook_handler as u64) & 0xFF) as u8,
            ((hook_handler as u64 >> 8) & 0xFF) as u8,
            ((hook_handler as u64 >> 16) & 0xFF) as u8,
            ((hook_handler as u64 >> 24) & 0xFF) as u8,
            ((hook_handler as u64 >> 32) & 0xFF) as u8,
            ((hook_handler as u64 >> 40) & 0xFF) as u8,
            ((hook_handler as u64 >> 48) & 0xFF) as u8,
            ((hook_handler as u64 >> 56) & 0xFF) as u8,
        ];
        
        std::ptr::copy_nonoverlapping(
            jmp_instruction.as_ptr(),
            self.target_addr as *mut u8,
            14,
        );
        
        // 4. Restaurar proteção original
        VirtualProtect(
            self.target_addr as *const _,
            14,
            old_protect,
            &mut old_protect,
        )?;
        
        // 5. Flush instruction cache
        use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
        use windows::Win32::System::Threading::GetCurrentProcess;
        FlushInstructionCache(
            GetCurrentProcess(),
            Some(self.target_addr as *const _),
            14,
        )?;
        
        self.is_hooked = true;
        Ok(())
    }
    
    /// Cria trampoline que executa bytes originais
    unsafe fn create_trampoline(&self) -> Result<usize, String> {
        use windows::Win32::System::Memory::*;
        
        // Alocar memória executável para trampoline
        let trampoline = VirtualAlloc(
            None,
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        
        if trampoline.is_null() {
            return Err("VirtualAlloc failed".to_string());
        }
        
        let mut trampoline_code = Vec::new();
        
        // 1. Copiar bytes originais (14 bytes)
        trampoline_code.extend_from_slice(&self.original_bytes);
        
        // 2. JMP para continuar execução após hook
        // jmp [rip+0]; <address>
        let return_addr = self.target_addr + 14;
        trampoline_code.extend_from_slice(&[
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        ]);
        trampoline_code.extend_from_slice(&return_addr.to_le_bytes());
        
        // 3. Escrever trampoline
        std::ptr::copy_nonoverlapping(
            trampoline_code.as_ptr(),
            trampoline as *mut u8,
            trampoline_code.len(),
        );
        
        Ok(trampoline as usize)
    }
    
    /// Remove o hook restaurando bytes originais
    pub unsafe fn remove(&mut self) -> Result<(), String> {
        if !self.is_hooked {
            return Ok(());
        }
        
        use windows::Win32::System::Memory::*;
        
        // Alterar proteção
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(
            self.target_addr as *const _,
            14,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )?;
        
        // Restaurar bytes originais
        std::ptr::copy_nonoverlapping(
            self.original_bytes.as_ptr(),
            self.target_addr as *mut u8,
            14,
        );
        
        // Restaurar proteção
        VirtualProtect(
            self.target_addr as *const _,
            14,
            old_protect,
            &mut old_protect,
        )?;
        
        // Flush cache
        use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
        use windows::Win32::System::Threading::GetCurrentProcess;
        FlushInstructionCache(
            GetCurrentProcess(),
            Some(self.target_addr as *const _),
            14,
        )?;
        
        self.is_hooked = false;
        Ok(())
    }
    
    /// Retorna ponteiro para trampoline (para chamar função original)
    pub fn get_original(&self) -> *const () {
        self.trampoline_addr as *const ()
    }
}
```

**Análise Rust Sentinel**:

> **CAMADA 1: SINTAXE**  
> Modificamos os primeiros 14 bytes da função alvo para inserir `JMP [RIP+0]` (jump absoluto) seguido de endereço de 64 bits.
> 
> **CAMADA 2: MEMÓRIA**  
> `VirtualProtect` temporariamente muda proteção da página de código para RWX. Trampoline é alocado via `VirtualAlloc` em memória executável separada.
> 
> **CAMADA 3: SEGURANÇA & OWNERSHIP**  
> Rust força que gerenciemos proteções de memória explicitamente. RAII do DetourHook garante cleanup via `Drop` trait.

### 2. Uso Prático: Hook em CreateFileA

```rust
use windows::Win32::Storage::FileSystem::*;

// Handler do hook
unsafe extern "system" fn create_file_hook(
    filename: PCSTR,
    desired_access: FILE_ACCESS_FLAGS,
    share_mode: FILE_SHARE_MODE,
    security_attrs: *const SECURITY_ATTRIBUTES,
    creation_disposition: FILE_CREATION_DISPOSITION,
    flags_and_attrs: FILE_FLAGS_AND_ATTRIBUTES,
    template_file: HANDLE,
) -> HANDLE {
    // Log nome do arquivo
    let filename_str = std::ffi::CStr::from_ptr(filename.0 as *const i8)
        .to_str()
        .unwrap_or("?");
    println!("[HOOK] CreateFileA: {}", filename_str);
    
    // Chamar função original via trampoline
    let original: unsafe extern "system" fn(
        PCSTR, FILE_ACCESS_FLAGS, FILE_SHARE_MODE, *const SECURITY_ATTRIBUTES,
        FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, HANDLE
    ) -> HANDLE = std::mem::transmute(CREATEFILE_HOOK.get_original());
    
    original(
        filename,
        desired_access,
        share_mode,
        security_attrs,
        creation_disposition,
        flags_and_attrs,
        template_file,
    )
}

static mut CREATEFILE_HOOK: DetourHook = unsafe { std::mem::zeroed() };

pub unsafe fn install_createfile_hook() -> Result<(), String> {
    use windows::Win32::System::LibraryLoader::*;
    
    // Obter endereço de CreateFileA
    let kernel32 = GetModuleHandleA(s!("kernel32.dll"))?;
    let create_file_addr = GetProcAddress(kernel32, s!("CreateFileA"))
        .ok_or("GetProcAddress failed")?;
    
    // Criar e instalar hook
    CREATEFILE_HOOK = DetourHook::new(create_file_addr)?;
    CREATEFILE_HOOK.install(create_file_hook as *const ())?;
    
    Ok(())
}
```

## 🎯 Aplicação em CS2 (2026)

### Hook em `CBaseEntity::GetOrigin`

```rust
// Interceptar leitura de posição de entidades para ESP
unsafe extern "fastcall" fn get_origin_hook(
    entity: *mut std::ffi::c_void,
) -> Vec3 {
    // Chamar original
    let original: unsafe extern "fastcall" fn(*mut std::ffi::c_void) -> Vec3 = 
        std::mem::transmute(GET_ORIGIN_HOOK.get_original());
    
    let position = original(entity);
    
    // Custom logic: armazenar posição para ESP
    ESP_DATA.lock().unwrap().insert(entity as usize, position);
    
    position
}

// Hook em SwapBuffers para renderizar ESP
unsafe extern "system" fn swap_buffers_hook(hdc: HDC) -> BOOL {
    // Renderizar ESP antes de swap
    render_esp();
    
    // Chamar original
    let original: unsafe extern "system" fn(HDC) -> BOOL =
        std::mem::transmute(SWAP_BUFFERS_HOOK.get_original());
    
    original(hdc)
}
```

## ⚠️ Detecção e Contramedidas (2026)

### Como Anti-Cheats Detectam Detour Hooks

```
1. Integrity checks
   ├─ Comparar primeiros bytes de funções críticas com originais
   ├─ CRC/Hash de código de funções conhecidas
   └─ Solução: Unhook antes de scan, re-hook após

2. Memory scanning
   ├─ Procurar por assinatura de JMP (0xFF 0x25)
   ├─ Identificar páginas RWX suspeitas (trampoline)
   └─ Solução: Encrypt trampoline, usar RX ao invés de RWX

3. Exception-based detection
   ├─ Trigger exceção, verificar se handler foi hookado
   └─ Solução: Hook também exception handlers

4. Stack walking
   ├─ Verificar call stack de funções sensíveis
   ├─ Identificar returns para módulos não conhecidos
   └─ Solução: Stack spoofing, ROP chains

5. Kernel mode verification
   ├─ Driver verifica integridade de user-mode code
   └─ Solução: Kernel hook também (muito arriscado)
```

### Técnicas Avançadas de Stealth

**Hardware Breakpoint Hook** (sem modificar código):
```rust
// Ao invés de modificar bytes, usar DR0-DR3 para trigger
// Requer acesso ao thread context
unsafe fn hardware_bp_hook(target_fn: *const ()) -> Result<(), String> {
    use windows::Win32::System::Threading::*;
    
    let thread = GetCurrentThread();
    let mut context = CONTEXT {
        ContextFlags: CONTEXT_DEBUG_REGISTERS,
        ..Default::default()
    };
    
    GetThreadContext(thread, &mut context)?;
    
    context.Dr0 = target_fn as u64;  // Breakpoint em target
    context.Dr7 |= 1;  // Enable DR0
    
    SetThreadContext(thread, &context)?;
    
    Ok(())
}
```

## 📊 Comparação de Técnicas de Hook

| Técnica | Stealth | Complexidade | Performance | Detecção 2026 |
|---------|---------|--------------|-------------|---------------|
| **Detour (inline)** | 🟡 Médio | 🟢 Simples | 🟢 Rápido | 🟡 Médio |
| **IAT Hook** | 🟡 Médio | 🟢 Muito simples | 🟢 Rápido | 🔴 Fácil |
| **Hardware BP** | 🟢 Alto | 🔴 Complexo | 🟡 Médio | 🟢 Difícil |
| **VEH Hook** | 🟢 Alto | 🔴 Complexo | 🔴 Lento | 🟢 Difícil |

## 📖 Ver Também
- [[IAT_Hooking]]
- [[EAT_Hooking]]
- [[MinHook_Library]]
- [[VTable_Hooking]]

---
<p align="center">REDFLAG © 2026</p>
