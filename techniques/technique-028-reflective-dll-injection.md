# 📖 Técnica 028: Reflective DLL Injection

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 028: Reflective DLL Injection]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Injection & Loading  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Reflective DLL Injection** carrega uma DLL diretamente na memória sem usar o loader do Windows, executando o código de inicialização manualmente. É mais stealth que LoadLibrary injection.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class ReflectiveInjector {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool ReflectiveInject(const char* dllPath) {
        // Carregar DLL localmente
        HMODULE hLocalDLL = LoadLibraryA(dllPath);
        if (!hLocalDLL) return false;
        
        // Obter informações da DLL
        DLL_REFLECTION_INFO reflectionInfo = GetReflectionInfo(hLocalDLL);
        
        // Alocar memória no processo remoto
        LPVOID remoteBase = VirtualAllocEx(hProcess, NULL, reflectionInfo.sizeOfImage,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) {
            FreeLibrary(hLocalDLL);
            return false;
        }
        
        // Copiar DLL para memória remota
        if (!CopyDLLToRemote(hLocalDLL, reflectionInfo, remoteBase)) {
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            FreeLibrary(hLocalDLL);
            return false;
        }
        
        // Criar bootstrap shellcode
        std::vector<BYTE> bootstrap = CreateBootstrapShellcode(remoteBase, reflectionInfo);
        
        // Alocar shellcode
        LPVOID shellcodeAddr = VirtualAllocEx(hProcess, NULL, bootstrap.size(),
                                            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!shellcodeAddr) {
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            FreeLibrary(hLocalDLL);
            return false;
        }
        
        // Injetar bootstrap
        if (!WriteProcessMemory(hProcess, shellcodeAddr, bootstrap.data(), bootstrap.size(), NULL)) {
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
            FreeLibrary(hLocalDLL);
            return false;
        }
        
        // Executar bootstrap
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                          (LPTHREAD_START_ROUTINE)shellcodeAddr,
                                          remoteBase, 0, NULL);
        
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
        
        // Limpar
        VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
        FreeLibrary(hLocalDLL);
        
        return true;
    }
    
private:
    DLL_REFLECTION_INFO GetReflectionInfo(HMODULE hDLL) {
        DLL_REFLECTION_INFO info = {0};
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hDLL;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)hDLL + dosHeader->e_lfanew);
        
        info.sizeOfImage = ntHeader->OptionalHeader.SizeOfImage;
        info.entryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;
        info.imageBase = ntHeader->OptionalHeader.ImageBase;
        
        // Encontrar função de reflexão (exportada como "ReflectiveLoader")
        info.reflectiveLoader = (REFLECTIVE_LOADER)GetProcAddress(hDLL, "ReflectiveLoader");
        
        return info;
    }
    
    bool CopyDLLToRemote(HMODULE hLocalDLL, const DLL_REFLECTION_INFO& info, LPVOID remoteBase) {
        // Copiar toda a imagem
        SIZE_T imageSize = info.sizeOfImage;
        if (!WriteProcessMemory(hProcess, remoteBase, hLocalDLL, imageSize, NULL)) {
            return false;
        }
        
        return true;
    }
    
    std::vector<BYTE> CreateBootstrapShellcode(LPVOID dllBase, const DLL_REFLECTION_INFO& info) {
        std::vector<BYTE> shellcode;
        
        // PUSH dllBase (parâmetro para ReflectiveLoader)
        shellcode.push_back(0x68); // PUSH imm32
        uintptr_t baseAddr = (uintptr_t)dllBase;
        shellcode.insert(shellcode.end(), (BYTE*)&baseAddr, (BYTE*)&baseAddr + 4);
        
        // MOV EAX, ReflectiveLoader
        shellcode.push_back(0xB8); // MOV EAX, imm32
        uintptr_t loaderAddr = (uintptr_t)info.reflectiveLoader;
        shellcode.insert(shellcode.end(), (BYTE*)&loaderAddr, (BYTE*)&loaderAddr + 4);
        
        // CALL EAX
        shellcode.push_back(0xFF);
        shellcode.push_back(0xD0);
        
        // RET
        shellcode.push_back(0xC3);
        
        return shellcode;
    }
};
```

### Reflective DLL Structure

```cpp
// Estrutura de uma DLL reflexiva
#pragma once

#include <Windows.h>
#include <stdint.h>

// Função de loader reflexivo
typedef HMODULE (WINAPI* REFLECTIVE_LOADER)(LPVOID);

// Estrutura para informações de reflexão
typedef struct _DLL_REFLECTION_INFO {
    DWORD sizeOfImage;
    DWORD entryPoint;
    uintptr_t imageBase;
    REFLECTIVE_LOADER reflectiveLoader;
} DLL_REFLECTION_INFO;

// Loader reflexivo exportado
extern "C" __declspec(dllexport) HMODULE ReflectiveLoader(LPVOID dllBase);

// Função de reflexão principal
HMODULE ReflectiveLoader(LPVOID dllBase) {
    // Obter headers PE
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)dllBase + dosHeader->e_lfanew);
    
    // Aplicar relocations se necessário
    uintptr_t delta = (uintptr_t)dllBase - ntHeader->OptionalHeader.ImageBase;
    if (delta != 0) {
        ApplyRelocations(dllBase, ntHeader, delta);
    }
    
    // Resolver imports
    ResolveImports(dllBase, ntHeader);
    
    // Proteger seções
    ProtectSections(dllBase, ntHeader);
    
    // Executar TLS callbacks
    ExecuteTLSCallbacks(dllBase, ntHeader);
    
    // Chamar entry point (DllMain)
    uintptr_t entryPoint = (uintptr_t)dllBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
    DLLMAIN dllMain = (DLLMAIN)entryPoint;
    
    dllMain((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, NULL);
    
    return (HMODULE)dllBase;
}

// Aplicar relocations
void ApplyRelocations(LPVOID dllBase, PIMAGE_NT_HEADER ntHeader, uintptr_t delta) {
    PIMAGE_DATA_DIRECTORY relocDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir->Size == 0) return;
    
    PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)dllBase + relocDir->VirtualAddress);
    
    while (relocBlock->VirtualAddress != 0) {
        DWORD numEntries = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD relocEntries = (PWORD)((BYTE*)relocBlock + sizeof(IMAGE_BASE_RELOCATION));
        
        for (DWORD i = 0; i < numEntries; i++) {
            WORD relocEntry = relocEntries[i];
            WORD type = relocEntry >> 12;
            WORD offset = relocEntry & 0xFFF;
            
            if (type == IMAGE_REL_BASED_HIGHLOW) {
                uintptr_t* patchAddr = (uintptr_t*)((BYTE*)dllBase + relocBlock->VirtualAddress + offset);
                *patchAddr += delta;
            }
        }
        
        relocBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)relocBlock + relocBlock->SizeOfBlock);
    }
}

// Resolver imports
void ResolveImports(LPVOID dllBase, PIMAGE_NT_HEADER ntHeader) {
    PIMAGE_DATA_DIRECTORY importDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size == 0) return;
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)dllBase + importDir->VirtualAddress);
    
    while (importDesc->Name != 0) {
        char* dllName = (char*)dllBase + importDesc->Name;
        
        HMODULE hModule = LoadLibraryA(dllName);
        if (!hModule) continue;
        
        if (importDesc->OriginalFirstThunk != 0) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)dllBase + importDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA funcThunk = (PIMAGE_THUNK_DATA)((BYTE*)dllBase + importDesc->FirstThunk);
            
            while (thunk->u1.AddressOfData != 0) {
                uintptr_t functionAddr = 0;
                
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    functionAddr = (uintptr_t)GetProcAddress(hModule, (char*)(thunk->u1.Ordinal & 0xFFFF));
                } else {
                    PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)dllBase + thunk->u1.AddressOfData);
                    functionAddr = (uintptr_t)GetProcAddress(hModule, importName->Name);
                }
                
                funcThunk->u1.Function = functionAddr;
                
                thunk++;
                funcThunk++;
            }
        }
        
        importDesc++;
    }
}

// Proteger seções
void ProtectSections(LPVOID dllBase, PIMAGE_NT_HEADER ntHeader) {
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
    
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER section = &sectionHeader[i];
        
        DWORD protect = 0;
        DWORD characteristics = section->Characteristics;
        
        if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
            protect = PAGE_EXECUTE;
        }
        if (characteristics & IMAGE_SCN_MEM_READ) {
            protect |= PAGE_READONLY;
        }
        if (characteristics & IMAGE_SCN_MEM_WRITE) {
            protect |= PAGE_READWRITE;
        }
        
        if (protect != 0) {
            uintptr_t sectionAddr = (uintptr_t)dllBase + section->VirtualAddress;
            SIZE_T sectionSize = section->Misc.VirtualSize;
            
            DWORD oldProtect;
            VirtualProtect((LPVOID)sectionAddr, sectionSize, protect, &oldProtect);
        }
    }
}

// Executar TLS callbacks
void ExecuteTLSCallbacks(LPVOID dllBase, PIMAGE_NT_HEADER ntHeader) {
    PIMAGE_DATA_DIRECTORY tlsDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir->Size == 0) return;
    
    PIMAGE_TLS_DIRECTORY tlsDirectory = (PIMAGE_TLS_DIRECTORY)((BYTE*)dllBase + tlsDir->VirtualAddress);
    
    if (tlsDirectory->AddressOfCallBacks != 0) {
        PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)((BYTE*)dllBase + tlsDirectory->AddressOfCallBacks);
        
        while (*callbacks != NULL) {
            (*callbacks)((LPVOID)dllBase, DLL_PROCESS_ATTACH, NULL);
            callbacks++;
        }
    }
}
```

### Por que é Detectado

> [!WARNING]
> **Reflective injection deixa rastros de shellcode e alocações suspeitas**

#### 1. Shellcode Detection
```cpp
// Detecção de shellcode reflexivo
class ShellcodeDetector {
private:
    std::set<uintptr_t> scannedRegions;
    
public:
    void ScanForShellcode(HANDLE hProcess) {
        EnumerateExecutableRegions(hProcess);
        
        for (uintptr_t region : scannedRegions) {
            if (IsReflectiveShellcode(hProcess, region)) {
                ReportReflectiveInjection(hProcess, region);
            }
        }
    }
    
    bool IsReflectiveShellcode(HANDLE hProcess, uintptr_t address) {
        // Ler shellcode
        std::vector<BYTE> code = ReadMemoryRegion(hProcess, address, SHELLCODE_SCAN_SIZE);
        if (code.empty()) return false;
        
        // Procurar padrões de reflective injection
        return HasReflectivePatterns(code);
    }
    
    bool HasReflectivePatterns(const std::vector<BYTE>& code) {
        // Padrão: PUSH dllBase; MOV EAX, ReflectiveLoader; CALL EAX
        if (code.size() < 15) return false;
        
        // PUSH imm32
        if (code[0] != 0x68) return false;
        
        // MOV EAX, imm32
        if (code[5] != 0xB8) return false;
        
        // CALL EAX
        if (code[10] != 0xFF || code[11] != 0xD0) return false;
        
        return true;
    }
    
    void OnMemoryAllocation(HANDLE hProcess, LPVOID address, SIZE_T size, DWORD protect) {
        if (protect & PAGE_EXECUTE) {
            scannedRegions.insert((uintptr_t)address);
        }
    }
    
private:
    void EnumerateExecutableRegions(HANDLE hProcess) {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t address = 0;
        
        while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi))) {
            if ((mbi.Protect & PAGE_EXECUTE) && mbi.State == MEM_COMMIT) {
                scannedRegions.insert((uintptr_t)mbi.BaseAddress);
            }
            
            address += mbi.RegionSize;
        }
    }
    
    std::vector<BYTE> ReadMemoryRegion(HANDLE hProcess, uintptr_t address, SIZE_T size) {
        std::vector<BYTE> buffer(size);
        SIZE_T bytesRead;
        
        if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer.data(), size, &bytesRead)) {
            buffer.resize(bytesRead);
            return buffer;
        }
        
        return {};
    }
};
```

#### 2. ReflectiveLoader Export Detection
```cpp
// Detecção de função ReflectiveLoader
class ReflectiveLoaderDetector {
private:
    std::map<HANDLE, std::set<std::string>> processExports;
    
public:
    void OnModuleLoad(HANDLE hProcess, HMODULE hModule) {
        // Escanear exports do módulo
        ScanModuleExports(hProcess, hModule);
        
        // Verificar se tem ReflectiveLoader
        if (HasReflectiveLoader(hProcess)) {
            ReportReflectiveDLL(hProcess);
        }
    }
    
    void ScanModuleExports(HANDLE hProcess, HMODULE hModule) {
        // Obter export table
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)hModule + dosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY exportDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        
        if (exportDir->Size == 0) return;
        
        PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDir->VirtualAddress);
        
        DWORD* nameTable = (DWORD*)((BYTE*)hModule + exportTable->AddressOfNames);
        WORD* ordinalTable = (WORD*)((BYTE*)hModule + exportTable->AddressOfNameOrdinals);
        
        for (DWORD i = 0; i < exportTable->NumberOfNames; i++) {
            char* functionName = (char*)hModule + nameTable[i];
            processExports[hProcess].insert(functionName);
        }
    }
    
    bool HasReflectiveLoader(HANDLE hProcess) {
        return processExports[hProcess].count("ReflectiveLoader") > 0;
    }
};
```

#### 3. Memory Pattern Analysis
```cpp
// Análise de padrões de memória reflexiva
class ReflectiveMemoryAnalyzer {
private:
    std::map<HANDLE, std::vector<MEMORY_PATTERN>> memoryPatterns;
    
public:
    void OnMemoryWrite(HANDLE hProcess, LPVOID address, SIZE_T size) {
        MEMORY_PATTERN pattern = AnalyzeMemoryPattern(hProcess, address, size);
        memoryPatterns[hProcess].push_back(pattern);
        
        if (IsReflectivePattern(pattern)) {
            ReportReflectiveInjection(hProcess, address);
        }
    }
    
    MEMORY_PATTERN AnalyzeMemoryPattern(HANDLE hProcess, LPVOID address, SIZE_T size) {
        MEMORY_PATTERN pattern = {0};
        pattern.address = (uintptr_t)address;
        pattern.size = size;
        
        // Ler dados
        std::vector<BYTE> data(size);
        ReadProcessMemory(hProcess, address, data.data(), size, NULL);
        
        // Calcular entropy
        pattern.entropy = CalculateEntropy(data);
        
        // Verificar se é código executável
        pattern.isExecutable = IsExecutableCode(data);
        
        // Verificar se tem strings suspeitas
        pattern.hasSuspiciousStrings = HasSuspiciousStrings(data);
        
        return pattern;
    }
    
    bool IsReflectivePattern(const MEMORY_PATTERN& pattern) {
        // Alta entropy + executável + strings suspeitas = reflective
        return pattern.entropy > HIGH_ENTROPY_THRESHOLD &&
               pattern.isExecutable &&
               pattern.hasSuspiciousStrings;
    }
    
    double CalculateEntropy(const std::vector<BYTE>& data) {
        std::map<BYTE, int> frequency;
        for (BYTE b : data) frequency[b]++;
        
        double entropy = 0.0;
        for (auto& pair : frequency) {
            double p = (double)pair.second / data.size();
            entropy -= p * log2(p);
        }
        
        return entropy;
    }
    
    bool IsExecutableCode(const std::vector<BYTE>& data) {
        // Verificar presença de opcodes comuns
        int opcodeCount = 0;
        for (size_t i = 0; i < data.size() - 1; i++) {
            BYTE b1 = data[i];
            BYTE b2 = data[i + 1];
            
            // CALL, JMP, PUSH, MOV, etc.
            if (IsCommonOpcode(b1, b2)) opcodeCount++;
        }
        
        return (double)opcodeCount / data.size() > EXECUTABLE_THRESHOLD;
    }
    
    bool HasSuspiciousStrings(const std::vector<BYTE>& data) {
        // Procurar por "ReflectiveLoader", "kernel32.dll", etc.
        std::string suspicious[] = {"ReflectiveLoader", "kernel32.dll", "LoadLibrary"};
        
        std::string dataStr(data.begin(), data.end());
        for (const std::string& str : suspicious) {
            if (dataStr.find(str) != std::string::npos) {
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
| VAC | Shellcode patterns | < 30s | 75% |
| VAC Live | Export scanning | Imediato | 80% |
| BattlEye | Memory analysis | < 1 min | 85% |
| Faceit AC | Entropy analysis | < 30s | 70% |

---

## 🔄 Alternativas Seguras

### 1. Thread Hijacking
```cpp
// ✅ Thread hijacking injection
class ThreadHijacker {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool HijackAndInject(const char* dllPath) {
        // Suspender thread alvo
        HANDLE hThread = FindTargetThread();
        if (!hThread) return false;
        
        SuspendThread(hThread);
        
        // Obter contexto
        CONTEXT context;
        context.ContextFlags = CONTEXT_FULL;
        GetThreadContext(hThread, &context);
        
        // Salvar contexto original
        CONTEXT originalContext = context;
        
        // Criar shellcode para LoadLibrary
        std::vector<BYTE> shellcode = CreateLoadLibraryShellcode(dllPath);
        
        // Alocar memória para shellcode
        LPVOID shellcodeAddr = VirtualAllocEx(hProcess, NULL, shellcode.size(),
                                            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!shellcodeAddr) {
            ResumeThread(hThread);
            return false;
        }
        
        // Injetar shellcode
        WriteProcessMemory(hProcess, shellcodeAddr, shellcode.data(), shellcode.size(), NULL);
        
        // Modificar RIP/RSP para executar shellcode
        context.Rip = (uintptr_t)shellcodeAddr;
        
        // PUSH return address (original RIP)
        context.Rsp -= 8;
        WriteProcessMemory(hProcess, (LPVOID)context.Rsp, &originalContext.Rip, 8, NULL);
        
        SetThreadContext(hThread, &context);
        
        // Resumir thread
        ResumeThread(hThread);
        
        // Aguardar execução
        Sleep(100);
        
        // Limpar
        VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
        
        CloseHandle(hThread);
        return true;
    }
    
private:
    HANDLE FindTargetThread() {
        // Encontrar thread adequada
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return NULL;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        
        DWORD processId = GetProcessId(hProcess);
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == processId) {
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (hThread) {
                        CloseHandle(hSnapshot);
                        return hThread;
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
        return NULL;
    }
    
    std::vector<BYTE> CreateLoadLibraryShellcode(const char* dllPath) {
        std::vector<BYTE> shellcode;
        
        // SUB RSP, 28h (shadow space)
        shellcode.push_back(0x48);
        shellcode.push_back(0x83);
        shellcode.push_back(0xEC);
        shellcode.push_back(0x28);
        
        // MOV RCX, dllPath
        shellcode.push_back(0x48);
        shellcode.push_back(0xB9);
        uintptr_t pathAddr = 0; // Placeholder
        shellcode.insert(shellcode.end(), (BYTE*)&pathAddr, (BYTE*)&pathAddr + 8);
        
        // MOV RAX, LoadLibraryA
        shellcode.push_back(0x48);
        shellcode.push_back(0xB8);
        uintptr_t loadLibraryAddr = (uintptr_t)LoadLibraryA;
        shellcode.insert(shellcode.end(), (BYTE*)&loadLibraryAddr, (BYTE*)&loadLibraryAddr + 8);
        
        // CALL RAX
        shellcode.push_back(0xFF);
        shellcode.push_back(0xD0);
        
        // ADD RSP, 28h
        shellcode.push_back(0x48);
        shellcode.push_back(0x83);
        shellcode.push_back(0xC4);
        shellcode.push_back(0x28);
        
        // RET
        shellcode.push_back(0xC3);
        
        return shellcode;
    }
};
```

### 2. APC Injection
```cpp
// ✅ APC injection
class APCInjector {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool APCInject(const char* dllPath) {
        // Alocar memória para DLL path
        LPVOID pathAddr = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pathAddr) return false;
        
        WriteProcessMemory(hProcess, pathAddr, dllPath, strlen(dllPath) + 1, NULL);
        
        // Encontrar thread alertável
        HANDLE hThread = FindAlertableThread();
        if (!hThread) {
            VirtualFreeEx(hProcess, pathAddr, 0, MEM_RELEASE);
            return false;
        }
        
        // Queue APC
        if (!QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)pathAddr)) {
            VirtualFreeEx(hProcess, pathAddr, 0, MEM_RELEASE);
            CloseHandle(hThread);
            return false;
        }
        
        // Aguardar execução
        Sleep(100);
        
        // Limpar
        VirtualFreeEx(hProcess, pathAddr, 0, MEM_RELEASE);
        CloseHandle(hThread);
        
        return true;
    }
    
private:
    HANDLE FindAlertableThread() {
        // Encontrar thread em estado alertável
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return NULL;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        
        DWORD processId = GetProcessId(hProcess);
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == processId) {
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (hThread) {
                        // Verificar se thread está alertável
                        if (IsThreadAlertable(hThread)) {
                            CloseHandle(hSnapshot);
                            return hThread;
                        }
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
        return NULL;
    }
    
    bool IsThreadAlertable(HANDLE hThread) {
        // Verificar se thread está em estado alertável
        // (simplificado - em prática seria mais complexo)
        return WaitForSingleObject(hThread, 0) == WAIT_TIMEOUT;
    }
};
```

### 3. Early Bird APC
```cpp
// ✅ Early bird APC injection
class EarlyBirdAPCInjector {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool EarlyBirdInject(const char* dllPath) {
        // Criar processo suspenso
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        char cmdLine[] = "notepad.exe";
        if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 
                          CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            return false;
        }
        
        // Injetar antes do processo começar
        if (!InjectViaAPC(pi.hThread, dllPath)) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }
        
        // Resumir processo
        ResumeThread(pi.hThread);
        
        // Aguardar um pouco
        Sleep(1000);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        return true;
    }
    
private:
    bool InjectViaAPC(HANDLE hThread, const char* dllPath) {
        // Alocar memória para path
        LPVOID pathAddr = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pathAddr) return false;
        
        WriteProcessMemory(hProcess, pathAddr, dllPath, strlen(dllPath) + 1, NULL);
        
        // Queue APC na thread principal
        if (!QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)pathAddr)) {
            VirtualFreeEx(hProcess, pathAddr, 0, MEM_RELEASE);
            return false;
        }
        
        return true;
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Reflective Detection
```cpp
// VAC reflective injection detection
class VAC_ReflectiveDetector {
private:
    ShellcodeDetector shellcodeDetector;
    ReflectiveLoaderDetector loaderDetector;
    ReflectiveMemoryAnalyzer memoryAnalyzer;
    
public:
    void Initialize() {
        shellcodeDetector.Initialize();
        loaderDetector.Initialize();
        memoryAnalyzer.Initialize();
    }
    
    void OnProcessAttach(HANDLE hProcess) {
        StartMonitoring(hProcess);
    }
    
    void OnMemoryAllocation(HANDLE hProcess, LPVOID address, SIZE_T size, DWORD protect) {
        shellcodeDetector.OnMemoryAllocation(hProcess, address, size, protect);
        memoryAnalyzer.OnMemoryAllocation(hProcess, address, size, protect);
    }
    
    void OnModuleLoad(HANDLE hProcess, HMODULE hModule) {
        loaderDetector.OnModuleLoad(hProcess, hModule);
    }
    
    void PeriodicScan(HANDLE hProcess) {
        shellcodeDetector.ScanForShellcode(hProcess);
    }
};
```

### BattlEye Reflective Analysis
```cpp
// BE reflective injection analysis
void BE_DetectReflectiveInjection() {
    // Monitor shellcode execution
    MonitorShellcodeExecution();
    
    // Scan for reflective loaders
    ScanForReflectiveLoaders();
    
    // Analyze memory entropy
    AnalyzeMemoryEntropy();
}

void MonitorShellcodeExecution() {
    // Track thread execution patterns
    // Detect abnormal control flow
}

void ScanForReflectiveLoaders() {
    // Look for ReflectiveLoader exports
    // Validate export tables
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | Básica |
| 2020-2024 | ⚠️ Médio risco | Shellcode patterns |
| 2025-2026 | ⚠️ Alto risco | Memory analysis |

---

## 🎯 Lições Aprendidas

1. **Shellcode é Detectado**: Padrões de bootstrap são identificados.

2. **Exports São Escaneados**: ReflectiveLoader é uma assinatura conhecida.

3. **Memória é Analisada**: Alta entropy e strings suspeitas são rastreadas.

4. **APC Injection é Mais Stealth**: Usar APCs é menos detectável.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#28]]
- [[Thread_Hijacking]]
- [[APC_Injection]]
- [[Early_Bird_APC]]

---

*Reflective DLL injection tem risco moderado. Considere APC injection para mais stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
