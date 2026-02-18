# ⏱️ Dynamic Behavior Analysis

📅 Criado em: 2026-02-15
🔗 Tags: #conceito #anti-cheat #runtime-analysis

## 📌 Definição

**Dynamic Behavior Analysis** é uma técnica de detecção que monitora o **comportamento em tempo de execução** de processos e drivers, procurando por padrões característicos de cheats. Diferente de análise estática (assinaturas), foca em **o que o código FAZ**, não em como ele parece.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[ML_Based_Detection]]
- [[Context_Aware_Detection]]
- [[Static_Analysis]]

## 📚 O Que é Monitorado

### 1. Padrões de API Calls
```
Comportamento Normal (Discord overlay):
CreateFileW("overlay.dll") → VirtualAlloc(RX) → CreateThread() → Sleep(16ms loop)

Comportamento Suspeito (DLL injector):
OpenProcess(PROCESS_ALL_ACCESS) → VirtualAllocEx() → WriteProcessMemory() 
→ CreateRemoteThread() → CloseHandle()
                    ↑
              Padrão clássico de injection
```

### 2. Frequência de Chamadas
```rust
// NORMAL: Overlay lê memória a ~60 FPS
ReadProcessMemory() @ 16ms intervals

// SUSPEITO: Triggerbot lê a CADA frame do kernel
ReadProcessMemory() @ 0.1ms intervals (10,000 Hz)
                    ↑
                Inumano, certamente bot
```

### 3. Call Stack Analysis
```
Legítimo:
user32.dll!GetCursorPos() ← game.exe!InputHandler()

Cheat:
kernelbase.dll!ReadProcessMemory() ← cheat.dll!GetPlayerPos()
                                   ↑
                         Não deveria estar lendo memória externa
```

## 🛠️ Técnicas do VAC Live (2026)

### Event Tracing for Windows (ETW)
```cpp
// VAC assina eventos de kernel
EtwEventRegister(&ProviderGuid, ...);
EtwEventWrite(RegHandle, &EventDescriptor, ...);

// Eventos monitorados:
- ImageLoad (DLL injection detection)
- ProcessCreate (launcher detection)  
- ThreadCreate (remote thread)
- ObjectHandle (PROCESS_VM_WRITE abuse)
```

### Kernel Callbacks
```cpp
// Driver do VAC registra callbacks
PsSetCreateProcessNotifyRoutine(OnProcessCreate);
PsSetLoadImageNotifyRoutine(OnImageLoad);
ObRegisterCallbacks(&CallbackRegistration);

// Detecta:
- Unsigned drivers sendo carregados
- Processos abrindo handle para cs2.exe
- Manipulação de Page Tables (CR3 swap)
```

## 🎯 Bypass de Dynamic Analysis

### 1. Throttling Inteligente
```rust
use std::time::{Duration, Instant};

static LAST_READ: Lazy<Mutex<Instant>> = Lazy::new(|| {
    Mutex::new(Instant::now())
});

fn read_player_health() -> i32 {
    let mut last = LAST_READ.lock().unwrap();
    let elapsed = last.elapsed();
    
    // Força mínimo de 16ms entre reads (60 FPS humano)
    if elapsed < Duration::from_millis(16) {
        std::thread::sleep(Duration::from_millis(16) - elapsed);
    }
    
    *last = Instant::now();
    unsafe { read_memory(PLAYER_BASE + HEALTH_OFFSET) }
}
```

### 2. API Unhooking
```rust
// Remove hooks do VAC em ntdll.sys
unsafe fn unhook_ntdll() {
    let ntdll_disk = read_clean_ntdll_from_disk();
    let ntdll_mem = get_module_base("ntdll.dll");
    
    // Restaura .text section original
    let mut old_protect = 0;
    VirtualProtect(ntdll_mem, 0x1000, PAGE_EXECUTE_READWRITE, &mut old_protect);
    memcpy(ntdll_mem, ntdll_disk.as_ptr(), ntdll_disk.len());
    VirtualProtect(ntdll_mem, 0x1000, old_protect, &mut old_protect);
}
```

### 3. Ofuscação de Call Stack
```rust
// Usa syscalls diretos para evitar user-mode hooks
#[naked]
unsafe extern "system" fn NtReadVirtualMemory(...) {
    asm!(
        "mov r10, rcx",
        "mov eax, 0x3F",  // Syscall number (NtReadVirtualMemory)
        "syscall",
        "ret",
        options(noreturn)
    );
}
```

## ⚠️ Sinais de Que Você Está Sendo Monitorado

> [!WARNING]
> Indicadores de Dynamic Behavior Analysis ativo:
> - Driver `vac.sys` carregado (óbvio, mas...)
> - Processos `svchost.exe` com threads suspeitas
> - ETW sessions ativas (`logman query -ets` mostra providers)
> - Latência inconsistente em syscalls (hooking detection)

## 📖 Ver Também
- [[Call_Stack_Analysis]]
- [[Hook_Detection]]
- [[Syscall_Hooking]]

---
<p align="center">REDFLAG © 2026</p>
