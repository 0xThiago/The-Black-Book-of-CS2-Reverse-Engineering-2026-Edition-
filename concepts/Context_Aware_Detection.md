# 🎭 Context Aware Detection

📅 Criado em: 2026-02-15
🔗 Tags: #conceito #anti-cheat #heuristics

## 📌 Definição

**Context-Aware Detection** é uma técnica de anti-cheat que analisa o **contexto completo** de uma ação suspeita, não apenas o dado isolado. Considera: estado do jogo, histórico do jogador, condições ambientais e correlação entre múltiplos sinais.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[ML_Based_Detection]]
- [[Dynamic_Behavior_Analysis]]
- [[Environmental_Awareness]]

## 📚 Exemplo: Headshot Detection

### Detecção Burra (Falso Positivo)
```python
if headshot_percentage > 50%:
    ban_player()  # Jogadores pro legítimos banidos!
```

### Detecção Context-Aware (VACnet 2026)
```python
def is_suspicious_headshot(player_stats, game_context):
    # CONTEXTO 1: Skill histórico
    if player_stats.avg_rank < "Gold" and headshot_rate > 60%:
        suspicion += 0.3
    
    # CONTEXTO 2: Situação do jogo
    if game_context.enemy_was_visible_for < 100ms:
        suspicion += 0.4  # Reação inumana
    
    # CONTEXTO 3: Padrão de mira
    if crosshair_movement == "instant_snap":
        suspicion += 0.5
    else if crosshair_movement == "smooth_bezier":
        suspicion -= 0.2  # Movimento natural
    
    # CONTEXTO 4: Correlação com outros eventos
    if recently_used_wallhack_angle:
        suspicion += 0.6
    
    return suspicion > THRESHOLD
```

## 🛡️ Como Anti-Cheats Usam Isso

### Valve VAC Live (CS2)
Coleta **150+ features contextuais**:
- Rank atual vs performance repentina
- Histórico de partidas (smurfing detection)
- Timing de cada ação (reaction time distribution)
- Movimentação de mira pré-engage (wallhack indicator)
- Economia do jogador (compra suspeita de AWP em eco)

### Riot Vanguard (Valorant)
- Correlaciona input de hardware com movimento na tela
- Detecta "impossibilidades físicas" (ex: 180° flick em <10ms)
- Analisa padrões de fumo/habilidades (ESP detection)

## 🎯 Bypass de Context-Aware Systems

### 1. Mimetismo Situacional
```rust
fn should_enable_aimbot(game_state: &GameState) -> bool {
    // Não use aimbot em situações "fáceis demais"
    if game_state.enemy_is_afk || game_state.enemy_health < 20 {
        return false; // Mataria naturalmente
    }
    
    // Não use se já está dominando
    if game_state.your_score > enemy_score + 10 {
        return false; // Evita overperformance flag
    }
    
    // Use apenas em clutches (contexto justifica)
    game_state.alive_teammates == 0 && game_state.alive_enemies >= 2
}
```

### 2. Consistência Temporal
```rust
// Mantenha estatísticas consistentes com seu rank
let target_headshot_rate = match player_rank {
    Rank::Silver => 0.15..0.25,
    Rank::Gold => 0.20..0.35,
    Rank::Global => 0.35..0.55,
};

// Throttle aimbot para não ultrapassar
if current_hs_rate > target_headshot_rate.end {
    disable_aimbot_this_round();
}
```

### 3. Injete "Erros Humanos" Contextualmente Corretos
```rust
// Erre mais quando está sob pressão (humano real faria isso)
let miss_chance = if is_being_flanked {
    0.4 // 40% chance de errar quando nervoso
} else {
    0.1 // 10% em situação calma
};
```

## ⚠️ Red Flags que Acionam Context-Aware

> [!CAUTION]
> Evite estes padrões que gritam "cheat" para sistemas contextuais:
> - ✅ Headshot rate **consistente** ao longo de 100 partidas
> - ❌ Headshot rate que **salta de 20% para 70%** repentinamente
> - ✅ Performance **compatível com rank**
> - ❌ Smurf óbvio (conta nova, 90% winrate, Global em 20 partidas)
> - ✅ Reação normal em situações normais
> - ❌ **Sempre** acertar o primeiro tiro ao virar esquina

## 📖 Ver Também
- [[Conditional_Behavior]]
- [[Environmental_Adaptation]]
- [[Delayed_Execution]]

---
<p align="center">REDFLAG © 2026</p>
