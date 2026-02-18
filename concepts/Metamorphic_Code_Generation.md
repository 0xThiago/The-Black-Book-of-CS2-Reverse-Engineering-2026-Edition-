# 🧪 Metamorphic Code Generation

📅 Criado em: 2026-02-15
🔗 Tags: #conceito #obfuscation #polymorphism

## 📌 Definição

**Metamorphic Code** é código que se reescreve completamente a cada execução, alterando sua estrutura interna enquanto mantém a mesma funcionalidade. Diferente de código polimórfico (que apenas muda a criptografia), código metamórfico muda a **lógica de implementação** em si.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[Técnica 049 - Anti-Reverse Engineering Techniques]]
- [[Code_Virtualization]]
- [[Polymorphic_Code]]

## 📚 Diferença: Polimórfico vs Metamórfico

| Aspecto | Polimórfico | Metamórfico |
|---------|-------------|-------------|
| **Lógica** | Mesma | Diferente |
| **Assinatura** | Muda (criptografia) | Muda (estrutura) |
| **Complexidade** | Baixa-Média | Alta |
| **Performance** | Impacto mínimo | Overhead moderado |

## 🛠️ Exemplo Conceitual

```rust
// Versão 1 (gerada em runtime)
fn check_aimbot_v1() -> bool {
    let a = get_player_pos();
    let b = get_enemy_pos();
    a.distance(b) < 100.0
}

// Versão 2 (mesma função, estrutura diferente)
fn check_aimbot_v2() -> bool {
    let enemy = get_enemy_pos();
    let player = get_player_pos();
    if player.x > enemy.x {
        return (player.x - enemy.x).abs() < 100.0;
    }
    false
}
```

## 🎯 Aplicação em Cheats CS2

### Geração de Múltiplas Versões
Cada build do cheat pode ter:
- **Ordem diferente de verificações**
- **Algoritmos equivalentes mas distintos**
- **Nomes de variáveis e estruturas únicos**

Isso quebra assinaturas baseadas em padrões de código.

## ⚠️ Limitações

> [!CAUTION]
> Metamorphic code **não esconde comportamento**. Se o VAC detecta que você está lendo `m_vecOrigin` de entidades, a estrutura do código é irrelevante. Foque em [[Hardware_Input_Methods]] ao invés de apenas ofuscação.

## 📖 Ver Também
- [[Runtime_Code_Generation]]
- [[JIT_Compilation]]
- [[Compile_Time_Obfuscation]]

---
<p align="center">REDFLAG © 2026</p>
