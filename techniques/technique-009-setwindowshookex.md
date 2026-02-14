# 📖 Técnica 008: SetWindowsHookEx

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ❌ Defasado / Ineficaz

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 008: SetWindowsHookEx]]

## 🔍 Desenvolvimento
> **Status:** ❌ Defasado / Ineficaz  
> **Risco de Detecção:** 🔴 Alto  
> **Domínio:** Hooks & Input  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**SetWindowsHookEx** é uma API do Windows usada para instalar hooks globais no sistema. Embora projetada para funcionalidades legítimas, é frequentemente abusada para interceptar input e modificar comportamento de jogos.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ❌ CÓDIGO DEFASADO - NÃO USE
HHOOK InstallGlobalHook() {
    // Instalar hook global para teclado
    return SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, 
                           GetModuleHandle(NULL), 0);
}

// Função de callback do hook
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* kbStruct = (KBDLLHOOKSTRUCT*)lParam;
        
        // Modificar input (exemplo: aimbot)
        if (kbStruct->vkCode == VK_LBUTTON && wParam == WM_KEYDOWN) {
            // Injetar mouse movement para aimbot
            InjectMouseMovement();
        }
        
        // Bloquear teclas suspeitas
        if (IsCheatKey(kbStruct->vkCode)) {
            return 1; // Bloquear tecla
        }
    }
    
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}
```

### Por que é Detectado

> [!WARNING]
> **Hooks globais são completamente visíveis e analisáveis**

#### 1. Hook Enumeration
```cpp
// Enumerar hooks instalados no sistema
void EnumerateHooks() {
    // Usar NtQueryInformationProcess com ProcessLdtInformation
    // ou enumerar via user32.dll exports
    
    HMODULE user32 = GetModuleHandleA("user32.dll");
    EnumHooks_t EnumHooks = (EnumHooks_t)GetProcAddress(user32, "EnumHooks");
    
    if (EnumHooks) {
        EnumHooks(EnumHookCallback, 0);
    }
}

BOOL CALLBACK EnumHookCallback(HHOOK hHook, LPARAM lParam) {
    // Obter informações do hook
    HOOKINFO hookInfo;
    if (GetHookInfo(hHook, &hookInfo)) {
        // Verificar se hook é suspeito
        if (IsSuspiciousHook(hookInfo)) {
            LogSuspiciousHook(hookInfo.hMod, hookInfo.hHook);
        }
    }
    
    return TRUE;
}
```

#### 2. Hook Chain Analysis
```cpp
// Analisar cadeia de hooks
void AnalyzeHookChain(int hookType) {
    HHOOK currentHook = GetFirstHook(hookType);
    
    while (currentHook) {
        // Obter informações do hook
        HOOKINFO info = GetHookInfo(currentHook);
        
        // Verificar módulo proprietário
        if (IsSuspiciousModule(info.hMod)) {
            ReportCheatHook(currentHook, info);
        }
        
        // Próximo hook na cadeia
        currentHook = GetNextHook(currentHook);
    }
}

HOOKINFO GetHookInfo(HHOOK hHook) {
    HOOKINFO info = {0};
    
    // Usar undocumented APIs para obter informações
    // ou analisar estrutura interna do hook
    
    return info;
}
```

#### 3. Module Validation
```cpp
// Validar módulos que instalam hooks
bool IsSuspiciousModule(HMODULE hModule) {
    if (!hModule) return true; // Hook sem módulo é suspeito
    
    char modulePath[MAX_PATH];
    if (GetModuleFileNameA(hModule, modulePath, MAX_PATH)) {
        // Verificar se módulo é do jogo ou sistema
        if (!IsTrustedPath(modulePath)) {
            return true;
        }
        
        // Verificar assinatura
        if (!IsSignedModule(modulePath)) {
            return true;
        }
        
        // Verificar se módulo está na lista de jogos
        if (!IsGameModule(modulePath)) {
            return true;
        }
    }
    
    return false;
}
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Hook enumeration | < 5 min | 95% |
| VAC Live | Chain analysis | < 1 min | 100% |
| BattlEye | Module validation | Imediato | 98% |
| Faceit AC | Hook scanning | < 30s | 90% |

---

## 🔄 Alternativas Seguras

### 1. DirectInput Hooking
```cpp
// ✅ Hook direto no DirectInput
class DirectInputHook {
private:
    IDirectInput8* pDirectInput;
    LPDIRECTINPUTDEVICE8 pKeyboard;
    LPDIRECTINPUTDEVICE8 pMouse;
    
public:
    void Initialize() {
        // Criar DirectInput
        DirectInput8Create(GetModuleHandle(NULL), DIRECTINPUT_VERSION,
                          IID_IDirectInput8, (LPVOID*)&pDirectInput, NULL);
        
        // Criar dispositivos
        pDirectInput->CreateDevice(GUID_SysKeyboard, &pKeyboard, NULL);
        pDirectInput->CreateDevice(GUID_SysMouse, &pMouse, NULL);
        
        // Hook vtable
        HookVTable(pKeyboard);
        HookVTable(pMouse);
    }
    
    void HookVTable(LPDIRECTINPUTDEVICE8 pDevice) {
        uintptr_t* vtable = *(uintptr_t**)pDevice;
        
        // Hook GetDeviceState
        OriginalGetDeviceState = (GetDeviceState_t)vtable[9];
        vtable[9] = (uintptr_t)HookedGetDeviceState;
    }
    
    HRESULT HookedGetDeviceState(DWORD cbData, LPVOID lpvData) {
        HRESULT hr = OriginalGetDeviceState(cbData, lpvData);
        
        if (SUCCEEDED(hr)) {
            // Modificar input aqui
            ModifyInput(lpvData, cbData);
        }
        
        return hr;
    }
};
```

### 2. Raw Input API
```cpp
// ✅ Raw Input processing
class RawInputProcessor {
public:
    void Initialize(HWND hwnd) {
        // Registrar raw input devices
        RAWINPUTDEVICE rid[2];
        
        // Keyboard
        rid[0].usUsagePage = 0x01;
        rid[0].usUsage = 0x06;
        rid[0].dwFlags = RIDEV_INPUTSINK;
        rid[0].hwndTarget = hwnd;
        
        // Mouse
        rid[1].usUsagePage = 0x01;
        rid[1].usUsage = 0x02;
        rid[1].dwFlags = RIDEV_INPUTSINK;
        rid[1].hwndTarget = hwnd;
        
        RegisterRawInputDevices(rid, 2, sizeof(RAWINPUTDEVICE));
    }
    
    void ProcessRawInput(HRAWINPUT hRawInput) {
        UINT dwSize;
        GetRawInputData(hRawInput, RID_INPUT, NULL, &dwSize, sizeof(RAWINPUTHEADER));
        
        LPBYTE lpb = new BYTE[dwSize];
        GetRawInputData(hRawInput, RID_INPUT, lpb, &dwSize, sizeof(RAWINPUTHEADER));
        
        RAWINPUT* raw = (RAWINPUT*)lpb;
        
        if (raw->header.dwType == RIM_TYPEKEYBOARD) {
            ProcessKeyboardInput(&raw->data.keyboard);
        } else if (raw->header.dwType == RIM_TYPEMOUSE) {
            ProcessMouseInput(&raw->data.mouse);
        }
        
        delete[] lpb;
    }
};
```

### 3. Kernel Input Filtering
```cpp
// ✅ Kernel-mode input filtering
NTSTATUS FilterInput(PDEVICE_OBJECT deviceObject, PIRP irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    
    if (stack->MajorFunction == IRP_MJ_READ) {
        // Modificar dados de input antes de enviar para usermode
        ModifyInputBuffer(irp->MdlAddress);
    }
    
    // Continuar processamento normal
    return OriginalDispatch(deviceObject, irp);
}

void ModifyInputBuffer(PMDL mdl) {
    PVOID buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    
    if (buffer) {
        // Aplicar modificações de aimbot/wallhack/etc
        ApplyCheatModifications(buffer);
    }
}
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Hook Scanner
```cpp
// VAC hook detection system
class VAC_HookScanner {
private:
    std::vector<HOOK_INFO> knownHooks;
    
public:
    void Initialize() {
        // Enumerar hooks legítimos na inicialização
        EnumerateSystemHooks();
        
        // Iniciar scanning periódico
        StartHookMonitoring();
    }
    
    void ScanForCheatHooks() {
        // Enumerar todos os hooks
        EnumHooks();
        
        // Comparar com baseline
        for (auto& hook : currentHooks) {
            if (!IsKnownHook(hook)) {
                ReportSuspiciousHook(hook);
            }
        }
    }
    
    void EnumHooks() {
        currentHooks.clear();
        
        // Usar undocumented functions para enumerar
        // ou analisar estruturas do kernel
    }
};
```

### BattlEye Hook Monitor
```cpp
// BE hook monitoring
void BE_MonitorHooks() {
    // Hook SetWindowsHookEx
    InstallHook("user32.dll", "SetWindowsHookExA", HookedSetWindowsHookExA);
    InstallHook("user32.dll", "SetWindowsHookExW", HookedSetWindowsHookExW);
    
    // Hook UnhookWindowsHookEx
    InstallHook("user32.dll", "UnhookWindowsHookEx", HookedUnhookWindowsHookEx);
}

HHOOK HookedSetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId) {
    // Verificar se hook é permitido
    if (IsBlockedHookType(idHook)) {
        LogBlockedHook(idHook, hMod);
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    
    // Verificar módulo
    if (!IsTrustedModule(hMod)) {
        LogUntrustedHookModule(hMod);
        ReportSuspiciousActivity();
    }
    
    return OriginalSetWindowsHookExA(idHook, lpfn, hMod, dwThreadId);
}

bool IsBlockedHookType(int idHook) {
    // Bloquear hooks de input
    return (idHook == WH_KEYBOARD || 
            idHook == WH_MOUSE || 
            idHook == WH_KEYBOARD_LL ||
            idHook == WH_MOUSE_LL);
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ⚠️ Risco | Básica |
| 2015-2020 | ❌ Detectado | Enumeration |
| 2020-2024 | ⛔ Alto risco | Analysis |
| 2025-2026 | ⛔ Crítico | AI patterns |

---

## 🎯 Lições Aprendidas

1. **Hooks São Visíveis**: Todos os hooks podem ser enumerados e analisados.

2. **Módulos São Verificados**: Proprietários de hooks são validados.

3. **Cadeias São Analisadas**: Sequências de hooks são examinadas.

4. **DirectInput é Superior**: Acesso direto aos dispositivos evita detecção.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#8]]
- [[DirectInput_Hooking]]
- [[Raw_Input_API]]
- [[Kernel_Input_Filtering]]

---

*SetWindowsHookEx é obsoleto. Use DirectInput hooking ou kernel input filtering em 2026.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
