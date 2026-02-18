# 🔐 Driver Filter Verification

📅 Criado em: 2026-02-15
🔗 Tags: #kernel #security #anti-cheat

## 📌 Definição

**Driver Filter Verification** é um mecanismo do Windows (introduzido no VAC Live) que valida a assinatura digital e integridade de drivers de filtro antes de permitir seu carregamento. Protege contra drivers maliciosos de cheat que tentam se infiltrar na stack de I/O do kernel.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[Técnica 012 - Kernel Driver]]
- [[Signed_Driver_Exploitation]]

## 📚 Como Funciona

### Verificações Realizadas
1. **Assinatura Digital Microsoft**
   - Driver deve ser assinado com certificado EV válido
   - Certificado não pode estar revogado
   
2. **Integrity Check (PatchGuard)**
   - Hash do `.sys` deve corresponder ao manifesto
   - Seções `.text` e `.data` não podem ser modificadas após load

3. **Callback Registration**
   - `ObRegisterCallbacks()` é monitorado
   - Lista de drivers permitidos é whitelist

## 🛡️ Bypass Techniques (2026)

### 1. Exploração de Drivers Legítimos
```rust
// Usa drivers já assinados e aprovados
const VULNERABLE_DRIVERS: &[&str] = &[
    "gdrv.sys",        // Gigabyte (CVE-2018-19320)
    "capcom.sys",      // Capcom (assinatura válida)
    "dbutil_2_3.sys",  // Dell BIOS Utility
];

// Carrega driver vulnerável e explora para exec code no kernel
unsafe fn exploit_signed_driver() -> Result<(), Error> {
    let handle = load_driver("gdrv.sys")?;
    // Usa IOCTL vulnerável para executar shellcode
    DeviceIoControl(handle, IOCTL_ARBITRARY_RW, ...);
}
```

### 2. BYOVD (Bring Your Own Vulnerable Driver)
```
[Seu Cheat] → Carrega driver assinado vulnerável
                    ↓
            Explora vulnerabilidade
                    ↓
         Executa payload não-assinado no Ring 0
```

### 3. DSE Bypass (Driver Signature Enforcement)
```rust
// Desabilita verificação temporariamente (requer admin)
unsafe fn disable_dse() {
    // Modifica g_CiEnabled no CI.dll
    let ci_base = get_module_base("ci.dll");
    let g_ci_enabled = ci_base + 0x12340; // Offset para flag
    
    let mut old_protect = 0;
    VirtualProtect(g_ci_enabled, 1, PAGE_READWRITE, &mut old_protect);
    *(g_ci_enabled as *mut u8) = 0; // Desabilita
}
```

## ⚠️ Riscos

> [!CAUTION]
> - Carregar drivers não-assinados **instantaneamente flagged** pelo VAC  
> - Exploits de drivers legítimos são **detectáveis via ETW**  
> - Cada patch do Windows pode **quebrar offsets de exploits**

## 📖 Ver Também
- [[Kernel_Manual_Mapping]]
- [[Physical_Memory_Access]]
- [[Technique 054: Rust Kernel RW]]

---
<p align="center">REDFLAG © 2026</p>
