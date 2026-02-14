# 📖 Técnica 007: LoadLibrary Injection

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ❌ Defasado / Ineficaz

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 007: LoadLibrary Injection]]

## 🔍 Desenvolvimento
> **Status:** ❌ Defasado / Ineficaz  
> **Risco de Detecção:** 🔴 Crítico  
> **Domínio:** DLL & Injeção  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**LoadLibrary Injection** é uma das técnicas mais antigas de injeção de DLLs em processos externos. Embora simples, é completamente detectável pelos sistemas anti-cheat modernos devido aos seus padrões característicos.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ❌ CÓDIGO DEFASADO - NÃO USE
BOOL InjectDLL_LoadLibrary(HANDLE hProcess, const char* dllPath) {
    // 1. Alocar memória para o path da DLL
    SIZE_T pathSize = strlen(dllPath) + 1;
    LPVOID remotePath = VirtualAllocEx(hProcess, NULL, pathSize, 
                                      MEM_COMMIT, PAGE_READWRITE);
    
    if (!remotePath) return FALSE;
    
    // 2. Escrever o path na memória alocada
    if (!WriteProcessMemory(hProcess, remotePath, dllPath, pathSize, NULL)) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // 3. Obter endereço de LoadLibraryA/W
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC loadLibrary = GetProcAddress(kernel32, "LoadLibraryA");
    
    // 4. Criar thread remoto para executar LoadLibrary
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)loadLibrary,
                                       remotePath, 0, NULL);
    
    if (!hThread) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // 5. Aguardar conclusão
    WaitForSingleObject(hThread, INFINITE);
    
    // 6. Obter resultado (handle da DLL)
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    
    // 7. Limpar
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    
    return exitCode != 0;
}
```

### Por que é Detectado

> [!DANGER]
> **LoadLibrary injection deixa rastros digitais em todos os módulos carregados**

#### 1. Module Enumeration
```cpp
// Enumerar módulos carregados
void EnumerateModules(DWORD processId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
    
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me;
        me.dwSize = sizeof(MODULEENTRY32);
        
        if (Module32First(hSnapshot, &me)) {
            do {
                AnalyzeModule(me);
            } while (Module32Next(hSnapshot, &me));
        }
        
        CloseHandle(hSnapshot);
    }
}

void AnalyzeModule(const MODULEENTRY32& module) {
    // Verificar se módulo é suspeito
    if (IsSuspiciousModule(module.szModule, module.szExePath)) {
        LogSuspiciousModule(module.th32ProcessID, module.szModule);
    }
    
    // Verificar timestamp de carregamento
    if (IsRecentlyLoaded(module)) {
        LogRecentModuleLoad(module);
    }
}
```

#### 2. LoadLibrary Hooks
```cpp
// Hook em LoadLibrary para detectar injeções
HMODULE WINAPI HookedLoadLibraryA(LPCSTR lpLibFileName) {
    // Verificar se chamada é de thread remoto
    if (IsRemoteThread()) {
        LogDLLInjection(lpLibFileName);
        ReportCheatDetected();
        
        // Possivelmente bloquear
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    
    return OriginalLoadLibraryA(lpLibFileName);
}

// Verificar se thread atual é remoto
bool IsRemoteThread() {
    DWORD currentThreadId = GetCurrentThreadId();
    DWORD currentProcessId = GetCurrentProcessId();
    
    // Verificar se thread pertence ao processo
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32ThreadID == currentThreadId) {
                    // Se owner process é diferente, é thread remoto
                    if (te.th32OwnerProcessID != currentProcessId) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                    break;
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
    }
    
    return false;
}
```

#### 3. DLL Load Order Analysis
```cpp
// Analisar ordem de carregamento de DLLs
class DLLLoadAnalyzer {
private:
    std::vector<DLL_LOAD_EVENT> loadEvents;
    
public:
    void OnDLLLoad(const char* dllName, DWORD timestamp) {
        DLL_LOAD_EVENT event = {dllName, timestamp};
        loadEvents.push_back(event);
        
        AnalyzeLoadPattern();
    }
    
    void AnalyzeLoadPattern() {
        // Padrão típico: kernel32.dll → user32.dll → suspeita.dll
        if (HasInjectionPattern()) {
            ReportDLLInjection();
        }
        
        // Verificar timestamps suspeitos
        if (HasSuspiciousTiming()) {
            ReportTimingAnomaly();
        }
    }
    
    bool HasInjectionPattern() {
        // Verificar sequência típica de injeção
        if (loadEvents.size() >= 3) {
            auto& recent = loadEvents.back();
            
            // DLL suspeita carregada recentemente
            if (IsSuspiciousDLL(recent.name) && 
                IsRecentLoad(recent.timestamp)) {
                return true;
            }
        }
        
        return false;
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Module enumeration | < 5 min | 100% |
| VAC Live | LoadLibrary hooks | Imediato | 100% |
| BattlEye | Load order analysis | < 30s | 98% |
| Faceit AC | Thread analysis | < 1 min | 95% |

---

## 🔄 Alternativas Seguras

### 1. Manual Mapping
```cpp
// ✅ Manual DLL mapping
class ManualMapper {
public:
    HMODULE MapDLL(HANDLE hProcess, const char* dllPath) {
        // 1. Ler DLL do disco
        std::vector<BYTE> dllData = ReadDLLFile(dllPath);
        
        // 2. Parse PE headers
        IMAGE_NT_HEADER* ntHeader = ParsePEHeaders(dllData);
        
        // 3. Alocar memória no processo alvo
        LPVOID remoteImage = AllocateRemoteMemory(hProcess, ntHeader->OptionalHeader.SizeOfImage);
        
        // 4. Map sections
        MapSections(hProcess, dllData, remoteImage, ntHeader);
        
        // 5. Fix imports
        FixImports(hProcess, remoteImage, ntHeader);
        
        // 6. Call entry point
        CallEntryPoint(hProcess, remoteImage, ntHeader);
        
        return (HMODULE)remoteImage;
    }
    
private:
    void MapSections(HANDLE hProcess, const std::vector<BYTE>& dllData, 
                    LPVOID remoteImage, IMAGE_NT_HEADER* ntHeader) {
        IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeader);
        
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            LPVOID sectionDest = (LPVOID)((uintptr_t)remoteImage + section->VirtualAddress);
            LPVOID sectionSrc = (LPVOID)((uintptr_t)dllData.data() + section->PointerToRawData);
            
            WriteProcessMemory(hProcess, sectionDest, sectionSrc, 
                             section->SizeOfRawData, NULL);
            
            section++;
        }
    }
};
```

### 2. Reflective DLL Injection
```cpp
// ✅ Reflective loading
class ReflectiveInjector {
public:
    HMODULE InjectReflective(HANDLE hProcess, const char* dllPath) {
        // 1. Ler DLL
        std::vector<BYTE> dllData = ReadDLLFile(dllPath);
        
        // 2. Alocar memória
        LPVOID remoteDLL = VirtualAllocEx(hProcess, NULL, dllData.size(),
                                         MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        
        // 3. Escrever DLL
        WriteProcessMemory(hProcess, remoteDLL, dllData.data(), dllData.size(), NULL);
        
        // 4. Executar loader refletivo
        return ExecuteReflectiveLoader(hProcess, remoteDLL);
    }
    
private:
    HMODULE ExecuteReflectiveLoader(HANDLE hProcess, LPVOID remoteDLL) {
        // Encontrar função de loader na DLL
        // Executar via thread ou APC
        // Retornar handle da DLL carregada
    }
};
```

### 3. Kernel DLL Loading
```cpp
// ✅ Kernel-mode DLL loading
NTSTATUS LoadDLLKernel(PEPROCESS targetProcess, const char* dllPath) {
    // 1. Ler DLL no kernel
    PVOID dllBuffer = ReadFileKernel(dllPath);
    
    // 2. Map no espaço de endereço do processo
    PVOID remoteImage = MmMapViewOfSection(targetProcess, dllBuffer);
    
    // 3. Fix relocations e imports
    FixRelocations(remoteImage);
    FixImports(remoteImage);
    
    // 4. Call DLL entry point
    CallEntryPointKernel(remoteImage);
    
    return STATUS_SUCCESS;
}
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Module Scanner
```cpp
// VAC module enumeration and analysis
class VAC_ModuleScanner {
private:
    std::set<std::string> legitimateModules;
    
public:
    void Initialize() {
        // Carregar lista de módulos legítimos
        LoadLegitimateModuleList();
        
        // Iniciar scanning periódico
        StartPeriodicScan();
    }
    
    void ScanModules(DWORD processId) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
        
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me = {sizeof(MODULEENTRY32)};
            
            if (Module32First(hSnapshot, &me)) {
                do {
                    if (!IsLegitimateModule(me.szModule)) {
                        ReportSuspiciousModule(processId, me.szModule, me.szExePath);
                    }
                } while (Module32Next(hSnapshot, &me));
            }
            
            CloseHandle(hSnapshot);
        }
    }
    
    bool IsLegitimateModule(const char* moduleName) {
        // Verificar se módulo está na lista branca
        return legitimateModules.find(moduleName) != legitimateModules.end();
    }
};
```

### BattlEye DLL Monitor
```cpp
// BE DLL loading monitor
void BE_MonitorDLLLoads() {
    // Hook LoadLibrary functions
    InstallHook("kernel32.dll", "LoadLibraryA", HookedLoadLibraryA);
    InstallHook("kernel32.dll", "LoadLibraryW", HookedLoadLibraryW);
    InstallHook("kernel32.dll", "LoadLibraryExA", HookedLoadLibraryExA);
    InstallHook("kernel32.dll", "LoadLibraryExW", HookedLoadLibraryExW);
}

HMODULE HookedLoadLibraryA(LPCSTR lpLibFileName) {
    // Verificar contexto de chamada
    if (IsSuspiciousContext()) {
        LogSuspiciousLoad(lpLibFileName);
        
        // Verificar se é DLL conhecida de cheat
        if (IsCheatDLL(lpLibFileName)) {
            ReportCheatDetected();
            return NULL;
        }
    }
    
    return OriginalLoadLibraryA(lpLibFileName);
}

bool IsSuspiciousContext() {
    // Verificar se chamado de thread remoto
    return IsRemoteThread();
    
    // Verificar stack trace
    return HasSuspiciousStack();
    
    // Verificar timing
    return IsUnexpectedLoad();
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ⚠️ Risco | Básica |
| 2015-2020 | ❌ Detectado | Hooks |
| 2020-2024 | ⛔ Alto risco | Analysis |
| 2025-2026 | ⛔ Crítico | AI patterns |

---

## 🎯 Lições Aprendidas

1. **Módulos São Enumeráveis**: Todas as DLLs carregadas podem ser listadas.

2. **LoadLibrary é Hookado**: Chamadas são interceptadas e analisadas.

3. **Ordem de Carregamento Importa**: Padrões de carregamento revelam injeções.

4. **Manual Mapping é Superior**: Evita hooks e detecção de módulos.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#7]]
- [[Manual_Mapping]]
- [[Reflective_Injection]]
- [[Kernel_DLL_Loading]]

---

*LoadLibrary injection é completamente obsoleto. Use manual mapping ou reflective injection em 2026.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
