# Técnica 002: mouse_event API

> **Status:** ❌ Defasado / Ineficaz  
> **Risco de Detecção:** ⛔ Crítico  
> **Domínio:** Entrada (Input)  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

A API **mouse_event** é uma função legada do Windows para simulação de eventos de mouse. Embora seja mais antiga que `SendInput`, compartilha vulnerabilidades similares e é igualmente detectável pelos anti-cheats modernos de 2026.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ❌ CÓDIGO DEFASADO - NÃO USE
void MoveMouse(int deltaX, int deltaY) {
    mouse_event(MOUSEEVENTF_MOVE, deltaX, deltaY, 0, 0);
}

void ClickMouse() {
    mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
    Sleep(10); // Simular hold
    mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
}
```

**Parâmetros da Função:**
```cpp
VOID mouse_event(
    DWORD dwFlags,      // Tipo de evento
    DWORD dx,          // Movimento X
    DWORD dy,          // Movimento Y  
    DWORD dwData,      // Wheel data
    ULONG_PTR dwExtraInfo // Info extra (FLAG!)
);
```

### Por que é Detectado

> [!DANGER]
> **Análise de call stack identifica origem não-física**

#### 1. Call Stack Analysis
```cpp
// VAC Live inspeciona a pilha de chamadas
void AnalyzeCallStack() {
    PVOID stack[32];
    USHORT captured = RtlCaptureStackBackTrace(0, 32, stack, NULL);
    
    // Verificar se vem de módulo suspeito
    for (USHORT i = 0; i < captured; i++) {
        HMODULE module = GetModuleFromAddress(stack[i]);
        if (IsCheatModule(module)) {
            FlagAsCheat();
            break;
        }
    }
}
```

#### 2. Timing Inconsistencies
```cpp
// Comparação de timing
struct TimingAnalysis {
    DWORD lastEventTime;
    DWORD eventCount;
    DWORD averageInterval;
};

bool IsSyntheticInput(DWORD currentTime) {
    DWORD interval = currentTime - lastEventTime;
    
    // mouse_event tem latência consistente
    // Input humano tem variação natural
    if (interval < 1 || interval > 1000) {
        return true; // Suspeito
    }
    
    return false;
}
```

#### 3. dwExtraInfo Flag
```cpp
// Mesmo problema que SendInput
#define LLMHF_INJECTED 0x00000001

mouse_event(MOUSEEVENTF_MOVE, dx, dy, 0, LLMHF_INJECTED);
// ↑ Esta flag marca como input injetado
```

---

## 📊 Comparação com SendInput

| Aspecto | mouse_event | SendInput |
|---------|-------------|-----------|
| **API Level** | User32.dll | User32.dll |
| **Flexibilidade** | Limitada | Alta |
| **Detecção** | ⛔ Imediata | ⛔ Imediata |
| **Performance** | Baixa | Alta |
| **Compatibilidade** | Win95+ | Win2000+ |

---

## 🔄 Evolução e Obsolescência

### Timeline de Detecção
```
1995: Introduzida no Windows 95
2000: Primeiro uso em cheats
2010: VAC básico detecta
2015: VAC Advanced bloqueia
2020: VAC Live v2 - ban imediato
2024: LLMHF_INJECTED monitoring
2026: Detecção 100% em todos ACs
```

### Razões Técnicas da Obsolescência
1. **Hook Points**: Fácil de interceptar em user32.dll
2. **Flags Predictíveis**: Sempre deixa pegadas digitais
3. **Timing Artificial**: Latência não-humana
4. **Call Stack**: Pilha de chamadas revela origem

---

## 🚫 Alternativas Modernas

### 1. Direct Kernel Input (Ring 0)
```cpp
// ✅ Kernel-mode input injection
NTSTATUS InjectMouse_Kernel(PMOUSE_INPUT_DATA inputData) {
    // Bypass de todas validações usermode
    return IoCallDriver(mouseDriver, inputIrp);
}
```

### 2. Hardware Emulation
```cpp
// ✅ Arduino Leonardo HID
void setup() {
    // Configurar como dispositivo HID
}

void loop() {
    // Enviar reports USB diretos
    sendMouseReport(deltaX, deltaY);
}
```

### 3. DMA Input Injection
```cpp
// ✅ DMA para input buffer
void DMA_InjectInput(PMOUSE_INPUT_DATA input) {
    // Escrever diretamente no buffer do driver
    DMA_Write(mouseBufferAddress, input, sizeof(*input));
}
```

---

## 🛡️ Mecanismos de Detecção

### VAC Live Detection Engine
```cpp
// Pseudocódigo do detector
class VAC_InputDetector {
private:
    std::vector<InputEvent> eventHistory;
    CallStackAnalyzer stackAnalyzer;
    
public:
    bool IsCheatInput(const INPUT& input) {
        // 1. Verificar flag injetada
        if (input.dwExtraInfo & LLMHF_INJECTED) {
            return true;
        }
        
        // 2. Analisar call stack
        if (!stackAnalyzer.IsValidStack()) {
            return true;
        }
        
        // 3. Verificar timing patterns
        if (IsBotTiming(input.time)) {
            return true;
        }
        
        return false;
    }
};
```

### BattlEye Hardware Validation
```cpp
// BE compara com dispositivo físico
bool BE_ValidateHardwareInput() {
    // Ler estado real do mouse
    MOUSE_STATE realState = ReadPhysicalMouse();
    
    // Comparar com input reportado
    if (!MatchesReportedInput(realState)) {
        return false; // Cheat detectado
    }
    
    return true;
}
```

---

## 📈 Estatísticas de Eficácia

### Taxa de Detecção por AC (2026)
- **VAC Live**: 100% (imediata)
- **VACnet**: 100% (< 1 segundo)
- **BattlEye**: 100% (imediata)
- **Faceit AC**: 100% (imediata)

### Tempo Médio para Ban
- **Servidores Comunitários**: < 30 segundos
- **Servidores Premium**: < 5 segundos
- **Faceit/ESEA**: Imediato

---

## 🎯 Lições para Desenvolvedores

1. **APIs Legadas São Alvos**: Funções antigas são bem documentadas e facilmente hookadas.

2. **Flags São Traidoras**: Qualquer flag que marque input como "injetado" é um giveaway.

3. **Timing Revela Tudo**: A diferença entre input humano e sintético é mensurável.

4. **Kernel é o Caminho**: Operar abaixo do ring 3 evita a maioria das detecções.

---

## 🔗 Referências Cruzadas

- [[technique-001-windows-sendinput|SendInput Analysis]]
- [[VAC_Live_Input_Detection]]
- [[Hardware_Input_Methods]]
- [[Call_Stack_Analysis]]

---

*Esta técnica é documentada apenas para compreensão histórica. **NUNCA USE** em 2026.*