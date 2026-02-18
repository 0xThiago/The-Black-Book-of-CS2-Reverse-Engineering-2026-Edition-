# 🔐 Encrypted Memory Management

📅 Criado em: 2026-02-15
🔗 Tags: #conceito #memory #encryption #stealth

## 📌 Definição

**Encrypted Memory Management** é uma técnica de proteção onde dados sensíveis na memória do processo (offsets, configurações, estados do cheat) são mantidos criptografados e apenas descriptografados momentaneamente durante o uso.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[Técnica 048 - Anti-Memory Dumping Techniques]]
- [[Secure_Memory_Allocator]]
- [[Memory_Obfuscation_Engine]]

## 📚 Motivação

### Por que Anti-Cheats Fazem Dump de Memória?
- Procurar por **string signatures** ("aimbot", "triggerbot", offsets hardcoded)
- Detectar **estruturas conhecidas** (configs de cheats públicos)
- Análise de **padrões de alocação** suspeitos

### Solução: Nunca Armazenar em Plain-Text
```rust
// ❌ RUIM - Offset visível em memória
const PLAYER_BASE: usize = 0x12AB5678;

// ✅ BOM - Offset criptografado
static ENCRYPTED_OFFSET: u64 = 0xDEADBEEF ^ 0x12AB5678;

fn get_player_base() -> usize {
    (ENCRYPTED_OFFSET ^ 0xDEADBEEF) as usize
}
```

## 🛠️ Implementação em Rust (XOR Stream Cipher)

```rust
use std::sync::Mutex;

/// Gerenciador de memória criptografada
pub struct EncryptedMemory {
    key: [u8; 32],
    data: Mutex<Vec<u8>>,
}

impl EncryptedMemory {
    pub fn new() -> Self {
        Self {
            key: Self::generate_key(),
            data: Mutex::new(Vec::new()),
        }
    }
    
    /// Escreve dados criptografados
    pub fn write(&self, plaintext: &[u8]) {
        let mut data = self.data.lock().unwrap();
        data.clear();
        for (i, byte) in plaintext.iter().enumerate() {
            data.push(byte ^ self.key[i % 32]);
        }
    }
    
    /// Lê e descriptografa temporariamente
    pub fn read<T>(&self, f: impl FnOnce(&[u8]) -> T) -> T {
        let data = self.data.lock().unwrap();
        let mut decrypted = Vec::with_capacity(data.len());
        for (i, byte) in data.iter().enumerate() {
            decrypted.push(byte ^ self.key[i % 32]);
        }
        // Descriptografado existe apenas no escopo desta closure
        f(&decrypted)
    }
    
    fn generate_key() -> [u8; 32] {
        // Gerar chave baseada em timestamp + RDTSC
        let mut key = [0u8; 32];
        unsafe { core::arch::x86_64::_rdrand64_step(&mut *(key.as_mut_ptr() as *mut u64)) };
        key
    }
}
```

## 🎯 Uso em Cheat para CS2

```rust
// Config do aimbot criptografada
static CONFIG: Lazy<EncryptedMemory> = Lazy::new(|| {
    let mut mem = EncryptedMemory::new();
    mem.write(&bincode::serialize(&AimbotConfig {
        fov: 5.0,
        smooth: 25.0,
        rcs_enabled: true,
    }).unwrap());
    mem
});

// Leitura pontual quando necessário
fn should_shoot() -> bool {
    CONFIG.read(|data| {
        let config: AimbotConfig = bincode::deserialize(data).unwrap();
        is_target_in_fov(config.fov)
    }) // Descriptografado é imediatamente destruído aqui
}
```

## ⚠️ Limitações

> [!WARNING]
> Encryption **não protege contra hooks**. Se o VAC houkar `ReadProcessMemory`, ele verá os dados descriptografados durante o acesso. Combine com [[PTE_Manipulation]] para esconder páginas de memória críticas.

## 📖 Ver Também
- [[Memory_Encryption]]
- [[Code_Obfuscation]]
- [[Runtime_Code_Generation]]

---
<p align="center">REDFLAG © 2026</p>
