# 🔬 Polymorphic Code

📅 Criado em: 2026-02-15
🔗 Tags: #conceito #obfuscation #encryption

## 📌 Definição

**Polymorphic Code** é código que muda seu formato binário a cada execução através de criptografia variável, mas mantém a mesma lógica de implementação. Diferente de código metamórfico, apenas a "embalagem" muda, não o conteúdo.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[Metamorphic_Code_Generation]]
- [[Code_Virtualization]]
- [[Runtime_Code_Generation]]

## 📚 Como Funciona

### Estrutura Básica
```
[Decryptor Stub] + [Encrypted Payload] + [Random Key]
       ↓
Durante execução:
1. Decryptor lê a chave
2. Descriptografa o payload
3. Executa o código real
4. Antes de sair, re-encripta com NOVA chave
```

## 🛠️ Implementação em Rust

```rust
use rand::Rng;
use std::arch::asm;

/// Engine de polimorfismo simples
pub struct PolymorphicEngine {
    original_code: Vec<u8>,
}

impl PolymorphicEngine {
    /// Gera variante criptografada do código
    pub fn mutate(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let key: u8 = rng.gen();
        
        let mut output = Vec::new();
        
        // Stub de descriptografia (muda a cada build)
        output.extend_from_slice(&self.generate_decryptor_stub(key));
        
        // Payload criptografado
        let encrypted: Vec<u8> = self.original_code
            .iter()
            .map(|b| b ^ key)
            .collect();
        output.extend_from_slice(&encrypted);
        
        output
    }
    
    fn generate_decryptor_stub(&self, key: u8) -> Vec<u8> {
        // Gera assembly x64 único para descriptografar
        // Versão simplificada - real usaria múltiplas variações
        vec![
            0x48, 0x31, 0xC0,           // xor rax, rax
            0xB0, key,                   // mov al, key
            0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00, // lea rdi, [payload]
            // ... loop de XOR ...
        ]
    }
}
```

## 🎯 Uso em Cheats CS2

### Polimorfismo de Config
```rust
// Cada execução gera binário diferente
fn encrypt_config(cfg: &AimbotConfig) -> Vec<u8> {
    let serialized = bincode::serialize(cfg).unwrap();
    let key = generate_random_key();
    
    serialized.iter()
        .zip(key.iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect()
}
```

### Problemas com Assinaturas
```
Build 1: E8 3A 12 4F ... (assinatura única)
Build 2: 9C 8D FF 01 ... (mesma função, bytes diferentes)
Build 3: 44 6B 22 AA ... (impossível criar signature estática)
```

## ⚠️ Limitações

> [!IMPORTANT]
> Polimorfismo **não esconde comportamento em runtime**. O VAC Live pode ainda detectar:
> - Calls para `ReadProcessMemory` em high-frequency
> - Padrões de acesso de memória suspeitos
> - Hooks em funções do jogo
> 
> Use como camada adicional, não como solução única.

## 📖 Ver Também
- [[Code_Obfuscation]]
- [[Compile_Time_Obfuscation]]
- [[JIT_Compilation]]

---
<p align="center">REDFLAG © 2026</p>
