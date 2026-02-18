# Técnica 019 - Memory Scanning

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ❌ Defasado / Ineficaz

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[Técnica 020 - Pattern Scanning]]
- [[DATABASE]]

## 🔍 Desenvolvimento
> **Status:** ❌ Defasado / Ineficaz  
> **Risco de Detecção:** 🔴 Alto  
> **Domínio:** Scanning & Detection  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Memory Scanning** envolve varrer a memória do processo em busca de valores específicos (offsets, ponteiros, estruturas). Embora útil para desenvolvimento, é facilmente detectável quando usado em cheats.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ❌ CÓDIGO DEFASADO - NÃO USE
class MemoryScanner {
private:
    HANDLE hProcess;
    uintptr_t moduleBase;
    SIZE_T moduleSize;
    
public:
    void Initialize(HANDLE process, uintptr_t base, SIZE_T size) {
        hProcess = process;
        moduleBase = base;
        moduleSize = size;
    }
    
    // Scanner básico de valores
    std::vector<uintptr_t> ScanValue(int value) {
        std::vector<uintptr_t> results;
        const SIZE_T bufferSize = 0x1000;
        BYTE buffer[bufferSize];
        
        for (uintptr_t address = moduleBase; 
             address < moduleBase + moduleSize; 
             address += bufferSize) {
            
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer, 
                                bufferSize, &bytesRead)) {
                
                // Procurar valor no buffer
                for (SIZE_T i = 0; i < bytesRead - sizeof(int); i++) {
                    int* ptr = (int*)&buffer[i];
                    if (*ptr == value) {
                        results.push_back(address + i);
                    }
                }
            }
        }
        
        return results;
    }
    
    // Scanner de ponteiros
    std::vector<uintptr_t> ScanPointer(uintptr_t targetAddress) {
        std::vector<uintptr_t> results;
        const SIZE_T bufferSize = 0x1000;
        BYTE buffer[bufferSize];
        
        for (uintptr_t address = moduleBase; 
             address < moduleBase + moduleSize; 
             address += bufferSize) {
            
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer, 
                                bufferSize, &bytesRead)) {
                
                // Procurar ponteiro no buffer
                for (SIZE_T i = 0; i < bytesRead - sizeof(uintptr_t); i++) {
                    uintptr_t* ptr = (uintptr_t*)&buffer[i];
                    if (*ptr == targetAddress) {
                        results.push_back(address + i);
                    }
                }
            }
        }
        
        return results;
    }
    
    // Scanner de strings
    std::vector<uintptr_t> ScanString(const char* targetString) {
        std::vector<uintptr_t> results;
        SIZE_T stringLen = strlen(targetString);
        const SIZE_T bufferSize = 0x1000;
        BYTE buffer[bufferSize];
        
        for (uintptr_t address = moduleBase; 
             address < moduleBase + moduleSize; 
             address += bufferSize) {
            
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer, 
                                bufferSize, &bytesRead)) {
                
                // Procurar string no buffer
                for (SIZE_T i = 0; i < bytesRead - stringLen; i++) {
                    if (memcmp(&buffer[i], targetString, stringLen) == 0) {
                        results.push_back(address + i);
                    }
                }
            }
        }
        
        return results;
    }
    
    // Scanner avançado com filtros
    std::vector<uintptr_t> ScanAdvanced(const SCAN_PATTERN& pattern) {
        std::vector<uintptr_t> results;
        const SIZE_T bufferSize = 0x1000;
        BYTE buffer[bufferSize];
        
        for (uintptr_t address = moduleBase; 
             address < moduleBase + moduleSize; 
             address += bufferSize) {
            
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer, 
                                bufferSize, &bytesRead)) {
                
                // Aplicar filtros e procurar padrão
                for (SIZE_T i = 0; i < bytesRead - pattern.size; i++) {
                    if (MatchesPattern(&buffer[i], pattern)) {
                        results.push_back(address + i);
                    }
                }
            }
        }
        
        return results;
    }
    
private:
    bool MatchesPattern(BYTE* data, const SCAN_PATTERN& pattern) {
        // Implementar matching com wildcards, etc.
        return false; // Placeholder
    }
};
```

### Por que é Detectado

> [!DANGER]
> **Memory scanning deixa rastros óbvios de acesso suspeito à memória**

#### 1. Memory Access Monitoring
```cpp
// Monitorar acessos à memória
void MonitorMemoryAccess() {
    // Hook ReadProcessMemory
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)OriginalReadProcessMemory, HookedReadProcessMemory);
    DetourTransactionCommit();
}

SIZE_T WINAPI HookedReadProcessMemory(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesRead
) {
    // Log do acesso
    LogMemoryAccess(hProcess, (uintptr_t)lpBaseAddress, nSize);
    
    // Verificar se é acesso suspeito
    if (IsSuspiciousMemoryAccess(hProcess, (uintptr_t)lpBaseAddress, nSize)) {
        ReportMemoryScanning();
    }
    
    return OriginalReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, 
                                   nSize, lpNumberOfBytesRead);
}

bool IsSuspiciousMemoryAccess(HANDLE hProcess, uintptr_t address, SIZE_T size) {
    // Acesso grande a módulo do jogo
    if (size > SUSPICIOUS_SIZE_THRESHOLD) {
        return true;
    }
    
    // Acesso sequencial (scanning)
    if (IsSequentialAccess(address)) {
        return true;
    }
    
    // Acesso a regiões críticas
    if (IsCriticalMemoryRegion(address)) {
        return true;
    }
    
    return false;
}

bool IsSequentialAccess(uintptr_t address) {
    static std::vector<uintptr_t> recentAccesses;
    recentAccesses.push_back(address);
    
    if (recentAccesses.size() > 10) {
        recentAccesses.erase(recentAccesses.begin());
    }
    
    // Verificar se acessos são sequenciais
    if (recentAccesses.size() >= 3) {
        bool sequential = true;
        uintptr_t expected = recentAccesses[0] + ACCESS_GRANULARITY;
        
        for (size_t i = 1; i < recentAccesses.size(); i++) {
            if (recentAccesses[i] != expected) {
                sequential = false;
                break;
            }
            expected += ACCESS_GRANULARITY;
        }
        
        return sequential;
    }
    
    return false;
}
```

#### 2. Pattern Analysis
```cpp
// Análise de padrões de scanning
class ScanPatternAnalyzer {
private:
    std::vector<MEMORY_ACCESS> accessLog;
    
public:
    void OnMemoryAccess(HANDLE hProcess, uintptr_t address, SIZE_T size) {
        MEMORY_ACCESS access = {hProcess, address, size, GetTickCount()};
        accessLog.push_back(access);
        
        AnalyzeScanPatterns();
    }
    
    void AnalyzeScanPatterns() {
        // Detectar scanning linear
        if (HasLinearScanPattern()) {
            ReportMemoryScanner();
        }
        
        // Detectar scanning de valores
        if (HasValueScanPattern()) {
            ReportValueScanner();
        }
        
        // Detectar scanning de ponteiros
        if (HasPointerScanPattern()) {
            ReportPointerScanner();
        }
    }
    
    bool HasLinearScanPattern() {
        if (accessLog.size() < 5) return false;
        
        // Verificar se acessos são lineares
        DWORD timeWindow = 1000; // 1 segundo
        DWORD currentTime = GetTickCount();
        
        std::vector<MEMORY_ACCESS> recentAccesses;
        for (auto& access : accessLog) {
            if (currentTime - access.timestamp < timeWindow) {
                recentAccesses.push_back(access);
            }
        }
        
        if (recentAccesses.size() < 5) return false;
        
        // Verificar espaçamento regular
        std::vector<uintptr_t> addresses;
        for (auto& access : recentAccesses) {
            addresses.push_back(access.address);
        }
        
        std::sort(addresses.begin(), addresses.end());
        
        // Calcular diferenças
        std::vector<uintptr_t> diffs;
        for (size_t i = 1; i < addresses.size(); i++) {
            diffs.push_back(addresses[i] - addresses[i-1]);
        }
        
        // Verificar se diferenças são similares (scanning)
        uintptr_t avgDiff = 0;
        for (uintptr_t diff : diffs) avgDiff += diff;
        avgDiff /= diffs.size();
        
        int similarCount = 0;
        for (uintptr_t diff : diffs) {
            if (abs((int)(diff - avgDiff)) < SCAN_GRANULARITY_THRESHOLD) {
                similarCount++;
            }
        }
        
        return (float)similarCount / diffs.size() > 0.8f; // 80% similar
    }
    
    bool HasValueScanPattern() {
        // Detectar scanning de valores específicos
        // Analisar conteúdo lido vs padrões conhecidos
        return false; // Implementação específica
    }
};
```

#### 3. Performance Impact Detection
```cpp
// Detectar impacto na performance
class PerformanceMonitor {
private:
    DWORD lastCheckTime;
    SIZE_T totalBytesRead;
    
public:
    void Initialize() {
        lastCheckTime = GetTickCount();
        totalBytesRead = 0;
    }
    
    void OnMemoryRead(SIZE_T bytesRead) {
        totalBytesRead += bytesRead;
        
        DWORD currentTime = GetTickCount();
        if (currentTime - lastCheckTime > 1000) { // Check every second
            AnalyzePerformance();
            lastCheckTime = currentTime;
            totalBytesRead = 0;
        }
    }
    
    void AnalyzePerformance() {
        // Alto volume de leitura = suspeito
        if (totalBytesRead > SUSPICIOUS_READ_THRESHOLD) {
            ReportHighMemoryUsage();
        }
        
        // Calcular taxa de leitura
        float readRate = (float)totalBytesRead / 1024.0f; // KB/s
        
        if (readRate > SUSPICIOUS_READ_RATE) {
            ReportMemoryScanning();
        }
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Access monitoring | Imediato | 95% |
| VAC Live | Pattern analysis | < 30s | 90% |
| BattlEye | Performance impact | < 1 min | 85% |
| Faceit AC | Sequential access | < 30s | 80% |

---

## 🔄 Alternativas Seguras

### 1. Static Analysis
```cpp
// ✅ Análise estática de binários
class StaticAnalyzer {
public:
    void AnalyzeBinary(const char* filePath) {
        // Carregar PE file
        std::vector<BYTE> fileData = ReadFile(filePath);
        
        // Parse PE headers
        IMAGE_NT_HEADER* ntHeader = ParsePE(fileData);
        
        // Encontrar offsets via signatures
        FindOffsetsBySignatures(fileData, ntHeader);
        
        // Encontrar vtables
        FindVTables(fileData, ntHeader);
        
        // Encontrar strings
        FindStrings(fileData, ntHeader);
    }
    
private:
    void FindOffsetsBySignatures(const std::vector<BYTE>& data, IMAGE_NT_HEADER* ntHeader) {
        // Usar signatures para encontrar funções/offsets
        std::vector<BYTE> signature = {0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00}; // mov rax, [rip+offset]
        
        for (size_t i = 0; i < data.size() - signature.size(); i++) {
            if (MatchesSignature(&data[i], signature)) {
                uintptr_t offset = i;
                // RVA to file offset conversion
                uintptr_t rva = FileOffsetToRVA(offset, ntHeader);
                offsets.push_back(rva);
            }
        }
    }
    
    void FindVTables(const std::vector<BYTE>& data, IMAGE_NT_HEADER* ntHeader) {
        // Encontrar vtables via RTTI ou padrões
        // Analisar .rdata section
    }
    
    void FindStrings(const std::vector<BYTE>& data, IMAGE_NT_HEADER* ntHeader) {
        // Extrair strings do binário
        // Indexar para busca rápida
    }
};
```

### 2. Dynamic Analysis with Symbols
```cpp
// ✅ Análise dinâmica com símbolos
class DynamicAnalyzer {
private:
    std::map<std::string, uintptr_t> symbolCache;
    
public:
    void Initialize() {
        // Carregar PDB ou criar symbol map
        LoadSymbols();
    }
    
    uintptr_t GetOffset(const std::string& symbolName) {
        auto it = symbolCache.find(symbolName);
        if (it != symbolCache.end()) {
            return it->second;
        }
        
        // Resolver dinamicamente
        return ResolveSymbol(symbolName);
    }
    
private:
    void LoadSymbols() {
        // Carregar symbols do PDB
        // Ou criar map manual de offsets
        symbolCache["dwLocalPlayer"] = 0xDEADBEEF;
        symbolCache["dwEntityList"] = 0xCAFEBABE;
        // ...
    }
    
    uintptr_t ResolveSymbol(const std::string& symbolName) {
        // Usar debug APIs para resolver
        // Ou pattern scanning limitado
        return 0;
    }
};
```

### 3. Signature-Based Finding
```cpp
// ✅ Busca baseada em signatures
class SignatureScanner {
private:
    std::vector<BYTE> moduleData;
    
public:
    void Initialize(const std::vector<BYTE>& data) {
        moduleData = data;
    }
    
    uintptr_t FindSignature(const std::vector<BYTE>& signature, 
                           const std::string& mask = "") {
        for (size_t i = 0; i < moduleData.size() - signature.size(); i++) {
            if (MatchesSignature(&moduleData[i], signature, mask)) {
                return i;
            }
        }
        
        return 0;
    }
    
    std::vector<uintptr_t> FindAllSignatures(const std::vector<BYTE>& signature,
                                           const std::string& mask = "") {
        std::vector<uintptr_t> results;
        
        for (size_t i = 0; i < moduleData.size() - signature.size(); i++) {
            if (MatchesSignature(&moduleData[i], signature, mask)) {
                results.push_back(i);
            }
        }
        
        return results;
    }
    
private:
    bool MatchesSignature(BYTE* data, const std::vector<BYTE>& signature, 
                         const std::string& mask) {
        if (mask.empty()) {
            return memcmp(data, signature.data(), signature.size()) == 0;
        }
        
        for (size_t i = 0; i < signature.size(); i++) {
            if (mask[i] != '?' && data[i] != signature[i]) {
                return false;
            }
        }
        
        return true;
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Memory Monitor
```cpp
// VAC memory access monitoring
class VAC_MemoryMonitor {
private:
    ScanPatternAnalyzer patternAnalyzer;
    PerformanceMonitor perfMonitor;
    
public:
    void Initialize() {
        // Instalar hooks
        InstallMemoryHooks();
        
        patternAnalyzer.Initialize();
        perfMonitor.Initialize();
    }
    
    void OnMemoryRead(HANDLE hProcess, uintptr_t address, SIZE_T size) {
        // Analisar padrões
        patternAnalyzer.OnMemoryAccess(hProcess, address, size);
        
        // Monitorar performance
        perfMonitor.OnMemoryRead(size);
        
        // Verificar acesso suspeito
        if (IsSuspiciousAccess(hProcess, address, size)) {
            ReportMemoryScanner();
        }
    }
    
    bool IsSuspiciousAccess(HANDLE hProcess, uintptr_t address, SIZE_T size) {
        // Grandes leituras
        if (size > LARGE_READ_THRESHOLD) return true;
        
        // Acesso a módulos do jogo
        if (IsGameModuleAddress(address)) return true;
        
        // Padrões de scanning
        return HasScanPattern();
    }
};
```

### BattlEye Memory Scanner
```cpp
// BE memory scanning detection
void BE_DetectMemoryScanning() {
    // Monitor read operations
    MonitorReadOperations();
    
    // Analyze access patterns
    AnalyzeAccessPatterns();
    
    // Check for known scanner signatures
    CheckScannerSignatures();
}

void MonitorReadOperations() {
    // Hook ReadProcessMemory
    // Track all read operations
}

void AnalyzeAccessPatterns() {
    // Look for sequential access
    // Detect scanning behavior
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ⚠️ Risco | Básica |
| 2015-2020 | ❌ Detectado | Access hooks |
| 2020-2024 | ⛔ Alto risco | Pattern analysis |
| 2025-2026 | ⛔ Crítico | AI detection |

---

## 🎯 Lições Aprendadas

1. **Acessos São Rastreados**: Toda leitura de memória é monitorada.

2. **Padrões São Analisados**: Scanning linear é facilmente detectado.

3. **Performance é Monitorada**: Alto uso de memória é suspeito.

4. **Análise Estática é Superior**: Encontrar offsets offline evita detecção.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#18]]
- [[Static_Analysis]]
- [[Dynamic_Analysis_with_Symbols]]
- [[Signature_Based_Finding]]

---

*Memory scanning é completamente obsoleto. Use análise estática e signatures para encontrar offsets.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
