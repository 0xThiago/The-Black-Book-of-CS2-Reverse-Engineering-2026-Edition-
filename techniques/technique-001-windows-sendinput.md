# Técnica 001: Windows SendInput

> **Status:** ❌ Defasado / Ineficaz  
> **Risco de Detecção:** ⛔ Crítico  
> **Domínio:** Entrada (Input)  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

A técnica **Windows SendInput** é um método clássico de injeção de entrada que utiliza a API padrão do Windows para simular eventos de mouse e teclado. Esta abordagem foi amplamente utilizada em cheats antigos, mas tornou-se completamente obsoleta em 2026 devido aos avanços nos sistemas anti-cheat.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ❌ CÓDIGO DEFASADO - NÃO USE
INPUT input = {0};
input.type = INPUT_MOUSE;
input.mi.dx = deltaX;           // Movimento X
input.mi.dy = deltaY;           // Movimento Y
input.mi.dwFlags = MOUSEEVENTF_MOVE;  // Tipo de evento
input.mi.time = 0;              // Timestamp (opcional)

SendInput(1, &input, sizeof(INPUT));
```

**Fluxo de Execução:**
1. Aplicação chama `SendInput()`
2. Kernel valida parâmetros
3. Evento é enfileirado no sistema
4. Driver de dispositivo processa o evento

### Por que é Detectado

> [!WARNING]
> **VAC Live monitora a flag LLMHF_INJECTED desde 2024**

#### 1. Flag LLMHF_INJECTED
```cpp
// Como o Windows marca inputs sintéticos
#define LLMHF_INJECTED 0x00000001  // Bit 0

typedef struct tagMOUSEHOOKSTRUCT {
    POINT   pt;             // Posição do cursor
    HWND    hwnd;           // Handle da janela
    UINT    wHitTestCode;   // Código de teste de hit
    ULONG   dwExtraInfo;    // Informações extras
} MOUSEHOOKSTRUCT, *PMOUSEHOOKSTRUCT;

// VAC Live verifica:
if (mouseHookStruct->dwExtraInfo & LLMHF_INJECTED) {
    // Input sintético detectado!
    ReportCheatActivity();
}
```

#### 2. Análise de Call Stack
```cpp
// VAC Live inspeciona a pilha de chamadas
void VAC_CheckCallStack() {
    PVOID callStack[64];
    USHORT frames = RtlCaptureStackBackTrace(0, 64, callStack, NULL);
    
    for (int i = 0; i < frames; i++) {
        if (IsKnownCheatModule(callStack[i])) {
            BanPlayer();
        }
    }
}
```

#### 3. Timing Analysis
```cpp
// Análise de frequência de polling
struct InputTiming {
    DWORD lastInputTime;
    DWORD inputCount;
    DWORD timeWindow;
};

bool IsBotLikeTiming(DWORD currentTime) {
    DWORD delta = currentTime - lastInputTime;
    
    // SendInput tem jitter de ~1ms
    // Mouse físico: ~0.125ms (8kHz)
    if (delta < 2) {  // Muito rápido para humano
        return true;
    }
    
    return false;
}
```

---

## 📊 Estatísticas de Detecção

| Sistema Anti-Cheat | Tempo para Detecção | Método |
|-------------------|-------------------|---------|
| VAC Live | Imediata | LLMHF_INJECTED flag |
| VACnet | < 5 segundos | Call stack analysis |
| BattlEye | Imediata | Input validation |
| Faceit AC | Imediata | Hardware verification |

---

## 🔄 Evolução Histórica

| Período | Status | Razão |
|---------|--------|-------|
| 2000-2010 | ✅ Funcional | ACs primitivos |
| 2010-2015 | ⚠️ Risco | VAC básico |
| 2015-2020 | ❌ Detectado | VAC Live v1 |
| 2020-2024 | ⛔ Ban imediato | VAC Live v2 |
| 2024+ | ⛔ Crítico | LLMHF_INJECTED monitoring |

---

## 🚫 Alternativas Recomendadas

### 1. Hardware HID Injection
```cpp
// ✅ RECOMENDADO: Sayo Device
class SayoDevice {
public:
    void MoveMouse(double deltaX, double deltaY) {
        // Movimento via USB físico - sem flags
        SendHIDReport(deltaX, deltaY);
    }
};
```

### 2. Kernel-Level Input
```cpp
// ✅ RECOMENDADO: Direct kernel input
NTSTATUS InjectInput_Kernel(PMOUSE_INPUT_DATA input) {
    // Bypass de todas as validações usermode
    return IoCallDriver(mouseDevice, irp);
}
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Live Detection
```cpp
// Como o VAC detecta SendInput
BOOL VAC_DetectSendInput() {
    // 1. Hook em NtUserSendInput
    if (OriginalNtUserSendInput) {
        // Verificar call stack
        if (!IsValidCallStack()) {
            return TRUE; // Cheat detectado
        }
    }
    
    // 2. Verificar flag injetada
    if (input->dwExtraInfo & LLMHF_INJECTED) {
        return TRUE;
    }
    
    return FALSE;
}
```

### BattlEye Detection
```cpp
// BattlEye input validation
void BE_ValidateInput(PINPUT input) {
    // Comparar com inputs de dispositivo real
    if (!MatchesPhysicalDevice(input)) {
        ReportCheat();
    }
    
    // Verificar timing patterns
    if (IsBotTiming(input->time)) {
        ReportCheat();
    }
}
```

---

## 📈 Impacto no Desenvolvimento

### Antes (2010-2020)
- ✅ Fácil implementação
- ✅ Boa performance
- ✅ Compatibilidade universal

### Agora (2026)
- ❌ Detecção 100%
- ❌ Ban imediato
- ❌ Sem utilidade prática

---

## 🎯 Lições Aprendidas

1. **APIs de Alto Nível São Monitoradas**: Qualquer função que permita injeção de input será eventualmente detectada.

2. **Flags de Sistema São Críticas**: O Windows deixa "pegadas digitais" em inputs sintéticos.

3. **Timing é Tudo**: A diferença entre input humano e sintético é mensurável em microssegundos.

4. **Hardware é o Caminho**: Soluções que operam no nível físico são muito mais difíceis de detectar.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#1]]
- [[VAC_Live_Analysis]]
- [[Input_Injection_Methods]]
- [[Hardware_vs_Software_Input]]

---

*Esta técnica é mantida apenas para fins educacionais. **NÃO USE** em produção.*