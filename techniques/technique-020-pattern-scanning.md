# 📖 Técnica 020: Pattern Scanning

🔗 Link do vídeo: Não informado
📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 020: Pattern Scanning]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Scanning & Detection  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Pattern Scanning** busca por sequências específicas de bytes (signatures) na memória ou arquivos binários. É mais sofisticado que memory scanning básico, mas ainda detectável se mal implementado.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class PatternScanner {
private:
    std::vector<BYTE> moduleData;
    uintptr_t moduleBase;
    
public:
    void Initialize(const std::vector<BYTE>& data, uintptr_t base) {
        moduleData = data;
        moduleBase = base;
    }
    
    // Scanner básico com máscara
    uintptr_t FindPattern(const BYTE* pattern, const char* mask) {
        SIZE_T patternLength = strlen(mask);
        
        for (SIZE_T i = 0; i < moduleData.size() - patternLength; i++) {
            bool found = true;
            
            for (SIZE_T j = 0; j < patternLength; j++) {
                if (mask[j] != '?' && moduleData[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            
            if (found) {
                return moduleBase + i;
            }
        }
        
        return 0;
    }
    
    // Scanner múltiplo
    std::vector<uintptr_t> FindAllPatterns(const BYTE* pattern, const char* mask) {
        std::vector<uintptr_t> results;
        SIZE_T patternLength = strlen(mask);
        
        for (SIZE_T i = 0; i < moduleData.size() - patternLength; i++) {
            bool found = true;
            
            for (SIZE_T j = 0; j < patternLength; j++) {
                if (mask[j] != '?' && moduleData[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            
            if (found) {
                results.push_back(moduleBase + i);
            }
        }
        
        return results;
    }
    
    // Scanner com wildcards avançados
    uintptr_t FindAdvancedPattern(const std::string& pattern) {
        // Suporte a wildcards como ??, **, etc.
        std::vector<BYTE> bytes;
        std::string mask;
        ParsePattern(pattern, bytes, mask);
        
        return FindPattern(bytes.data(), mask.c_str());
    }
    
    // Scanner de IDA-style signatures
    uintptr_t FindIDASignature(const std::string& idaSig) {
        // Converter signature IDA para bytes/mask
        std::vector<BYTE> bytes;
        std::string mask;
        ParseIDASignature(idaSig, bytes, mask);
        
        return FindPattern(bytes.data(), mask.c_str());
    }
    
    // Scanner otimizado com Boyer-Moore
    uintptr_t FindPatternBoyerMoore(const BYTE* pattern, SIZE_T patternLength) {
        // Implementar algoritmo Boyer-Moore para performance
        std::vector<int> badChar = BuildBadCharTable(pattern, patternLength);
        std::vector<int> goodSuffix = BuildGoodSuffixTable(pattern, patternLength);
        
        int i = 0;
        while (i <= (int)moduleData.size() - (int)patternLength) {
            int j = patternLength - 1;
            
            while (j >= 0 && pattern[j] == moduleData[i + j]) {
                j--;
            }
            
            if (j < 0) {
                return moduleBase + i; // Found
            } else {
                int badCharShift = badChar[moduleData[i + j]];
                int goodSuffixShift = goodSuffix[j];
                i += std::max(badCharShift, goodSuffixShift);
            }
        }
        
        return 0;
    }
    
private:
    void ParsePattern(const std::string& pattern, std::vector<BYTE>& bytes, std::string& mask) {
        // Parse pattern like "48 8B 05 ?? ?? ?? ??"
        std::istringstream iss(pattern);
        std::string token;
        
        while (iss >> token) {
            if (token == "??") {
                bytes.push_back(0);
                mask.push_back('?');
            } else {
                bytes.push_back((BYTE)std::stoul(token, nullptr, 16));
                mask.push_back('x');
            }
        }
    }
    
    void ParseIDASignature(const std::string& idaSig, std::vector<BYTE>& bytes, std::string& mask) {
        // Parse IDA signatures como "48 8B 05 ? ? ? ?"
        ParsePattern(idaSig, bytes, mask);
    }
    
    std::vector<int> BuildBadCharTable(const BYTE* pattern, SIZE_T length) {
        const int ALPHABET_SIZE = 256;
        std::vector<int> badChar(ALPHABET_SIZE, -1);
        
        for (SIZE_T i = 0; i < length; i++) {
            badChar[pattern[i]] = i;
        }
        
        return badChar;
    }
    
    std::vector<int> BuildGoodSuffixTable(const BYTE* pattern, SIZE_T length) {
        std::vector<int> goodSuffix(length, 0);
        std::vector<int> suffixes(length, 0);
        
        // Calcular sufixos
        int len = 0;
        int i = length - 1;
        suffixes[i] = length;
        
        for (int j = i - 1; j >= 0; j--) {
            if (j > i && suffixes[j + length - 1 - len] < j - i) {
                suffixes[j] = suffixes[j + length - 1 - len];
            } else {
                if (j < i) i = j;
                while (i >= 0 && pattern[i] == pattern[length - 1 - (j - i)]) {
                    i--;
                }
                suffixes[j] = j - i;
            }
        }
        
        // Preencher good suffix table
        for (int j = 0; j < length - 1; j++) {
            goodSuffix[j] = length - 1 - suffixes[j];
        }
        
        return goodSuffix;
    }
};
```

### Por que é Detectado

> [!WARNING]
> **Pattern scanning deixa rastros quando acessa memória do processo alvo**

#### 1. Memory Access Detection
```cpp
// Detectar acessos à memória para scanning
class MemoryAccessDetector {
private:
    std::map<HANDLE, std::vector<MEMORY_ACCESS>> accessLog;
    
public:
    void OnMemoryRead(HANDLE hProcess, uintptr_t address, SIZE_T size) {
        MEMORY_ACCESS access = {address, size, GetTickCount()};
        accessLog[hProcess].push_back(access);
        
        // Limpar acessos antigos
        CleanOldAccesses(hProcess);
        
        // Analisar padrões
        if (IsPatternScanning(hProcess)) {
            ReportPatternScanner();
        }
    }
    
    bool IsPatternScanning(HANDLE hProcess) {
        auto& accesses = accessLog[hProcess];
        if (accesses.size() < 10) return false;
        
        // Verificar se acessos são pequenos e frequentes
        SIZE_T totalSize = 0;
        for (auto& access : accesses) {
            totalSize += access.size;
        }
        
        float avgSize = (float)totalSize / accesses.size();
        
        // Pattern scanning geralmente lê pequenos blocos
        if (avgSize > SMALL_READ_THRESHOLD) return false;
        
        // Verificar frequência
        DWORD timeSpan = accesses.back().timestamp - accesses.front().timestamp;
        float accessRate = (float)accesses.size() / (timeSpan / 1000.0f);
        
        if (accessRate > HIGH_ACCESS_RATE) {
            return true;
        }
        
        return false;
    }
    
private:
    void CleanOldAccesses(HANDLE hProcess) {
        auto& accesses = accessLog[hProcess];
        DWORD currentTime = GetTickCount();
        DWORD timeWindow = 5000; // 5 segundos
        
        accesses.erase(
            std::remove_if(accesses.begin(), accesses.end(),
                [currentTime, timeWindow](const MEMORY_ACCESS& access) {
                    return currentTime - access.timestamp > timeWindow;
                }),
            accesses.end()
        );
    }
};
```

#### 2. Signature Analysis
```cpp
// Detectar signatures conhecidas de scanners
class SignatureDetector {
private:
    std::vector<std::string> knownSignatures;
    
public:
    void Initialize() {
        // Signatures conhecidas de pattern scanners
        knownSignatures = {
            "48 8B 05 ?? ?? ?? ??", // Common pattern
            "FF 15 ?? ?? ?? ??",    // Call through IAT
            "E8 ?? ?? ?? ??",       // Call relative
            // Adicionar mais signatures
        };
    }
    
    bool IsKnownScannerSignature(const std::vector<BYTE>& code) {
        for (const std::string& sig : knownSignatures) {
            std::vector<BYTE> bytes;
            std::string mask;
            ParseSignature(sig, bytes, mask);
            
            if (MatchesSignature(code, bytes, mask)) {
                return true;
            }
        }
        
        return false;
    }
    
private:
    void ParseSignature(const std::string& sig, std::vector<BYTE>& bytes, std::string& mask) {
        std::istringstream iss(sig);
        std::string token;
        
        while (iss >> token) {
            if (token == "??") {
                bytes.push_back(0);
                mask.push_back('?');
            } else {
                bytes.push_back((BYTE)std::stoul(token, nullptr, 16));
                mask.push_back('x');
            }
        }
    }
    
    bool MatchesSignature(const std::vector<BYTE>& code, const std::vector<BYTE>& pattern, const std::string& mask) {
        if (code.size() < pattern.size()) return false;
        
        for (size_t i = 0; i < pattern.size(); i++) {
            if (mask[i] != '?' && code[i] != pattern[i]) {
                return false;
            }
        }
        
        return true;
    }
};
```

#### 3. Behavioral Analysis
```cpp
// Análise comportamental de pattern scanning
class BehavioralAnalyzer {
private:
    std::map<std::string, SCAN_BEHAVIOR> behaviorPatterns;
    
public:
    void Initialize() {
        // Definir padrões comportamentais
        behaviorPatterns["pattern_scan"] = {
            .minAccessRate = 100.0f,
            .maxAvgSize = 1024,
            .timeWindow = 3000,
            .confidence = 0.8f
        };
    }
    
    float AnalyzeBehavior(HANDLE hProcess, const std::vector<MEMORY_ACCESS>& accesses) {
        if (accesses.size() < 5) return 0.0f;
        
        // Calcular métricas
        float accessRate = CalculateAccessRate(accesses);
        SIZE_T avgSize = CalculateAverageSize(accesses);
        float sequentiality = CalculateSequentiality(accesses);
        
        // Comparar com padrões conhecidos
        float maxConfidence = 0.0f;
        
        for (auto& pattern : behaviorPatterns) {
            float confidence = CalculatePatternConfidence(
                pattern.second, accessRate, avgSize, sequentiality);
            
            maxConfidence = std::max(maxConfidence, confidence);
        }
        
        return maxConfidence;
    }
    
private:
    float CalculateAccessRate(const std::vector<MEMORY_ACCESS>& accesses) {
        if (accesses.size() < 2) return 0.0f;
        
        DWORD timeSpan = accesses.back().timestamp - accesses.front().timestamp;
        if (timeSpan == 0) return 0.0f;
        
        return (float)accesses.size() / (timeSpan / 1000.0f);
    }
    
    SIZE_T CalculateAverageSize(const std::vector<MEMORY_ACCESS>& accesses) {
        SIZE_T total = 0;
        for (auto& access : accesses) {
            total += access.size;
        }
        return total / accesses.size();
    }
    
    float CalculateSequentiality(const std::vector<MEMORY_ACCESS>& accesses) {
        if (accesses.size() < 3) return 0.0f;
        
        int sequentialCount = 0;
        for (size_t i = 1; i < accesses.size(); i++) {
            uintptr_t diff = accesses[i].address - accesses[i-1].address;
            if (diff > 0 && diff < SEQUENTIAL_THRESHOLD) {
                sequentialCount++;
            }
        }
        
        return (float)sequentialCount / (accesses.size() - 1);
    }
    
    float CalculatePatternConfidence(const SCAN_BEHAVIOR& pattern, 
                                   float accessRate, SIZE_T avgSize, float sequentiality) {
        float confidence = 0.0f;
        
        // Access rate match
        if (accessRate >= pattern.minAccessRate) {
            confidence += 0.4f;
        }
        
        // Average size match
        if (avgSize <= pattern.maxAvgSize) {
            confidence += 0.3f;
        }
        
        // Sequentiality match
        if (sequentiality > 0.7f) {
            confidence += 0.3f;
        }
        
        return confidence;
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Memory access patterns | < 30s | 75% |
| VAC Live | Signature analysis | Imediato | 85% |
| BattlEye | Behavioral analysis | < 1 min | 80% |
| Faceit AC | Access rate monitoring | < 30s | 70% |

---

## 🔄 Alternativas Seguras

### 1. Pre-computed Offsets
```cpp
// ✅ Offsets pré-calculados
class OffsetManager {
private:
    std::map<std::string, uintptr_t> offsets;
    
public:
    void Initialize() {
        // Offsets para versão específica do jogo
        offsets["dwLocalPlayer"] = 0xDEADBEEF;
        offsets["dwEntityList"] = 0xCAFEBABE;
        offsets["dwViewMatrix"] = 0x12345678;
        // ... mais offsets
    }
    
    uintptr_t GetOffset(const std::string& name) {
        auto it = offsets.find(name);
        return it != offsets.end() ? it->second : 0;
    }
    
    // Atualizar offsets para nova versão
    void UpdateOffsets(const std::map<std::string, uintptr_t>& newOffsets) {
        offsets = newOffsets;
    }
};
```

### 2. Symbol Resolution
```cpp
// ✅ Resolução de símbolos
class SymbolResolver {
private:
    HMODULE hGameModule;
    std::map<std::string, uintptr_t> symbolCache;
    
public:
    void Initialize(HMODULE hModule) {
        hGameModule = hModule;
        LoadSymbols();
    }
    
    uintptr_t ResolveSymbol(const std::string& symbolName) {
        auto it = symbolCache.find(symbolName);
        if (it != symbolCache.end()) {
            return it->second;
        }
        
        // Tentar resolver dinamicamente
        return GetProcAddress(hGameModule, symbolName.c_str());
    }
    
private:
    void LoadSymbols() {
        // Carregar symbols se disponível
        // Ou usar mapa manual
        symbolCache["CreateInterface"] = (uintptr_t)GetProcAddress(hGameModule, "CreateInterface");
        // ... mais símbolos
    }
};
```

### 3. Static Analysis Tools
```cpp
// ✅ Ferramentas de análise estática
class StaticAnalyzer {
public:
    void AnalyzeBinary(const char* filePath) {
        // Carregar e analisar binário
        std::vector<BYTE> fileData = LoadFile(filePath);
        
        // Encontrar exports
        FindExports(fileData);
        
        // Encontrar imports
        FindImports(fileData);
        
        // Encontrar vtables
        FindVTables(fileData);
        
        // Gerar mapa de offsets
        GenerateOffsetMap(fileData);
    }
    
private:
    void FindExports(const std::vector<BYTE>& data) {
        // Parse export table
        IMAGE_NT_HEADER* ntHeader = GetNTHeader(data);
        IMAGE_EXPORT_DIRECTORY* exportDir = GetExportDirectory(data, ntHeader);
        
        if (exportDir) {
            DWORD* functions = (DWORD*)&data[exportDir->AddressOfFunctions];
            DWORD* names = (DWORD*)&data[exportDir->AddressOfNames];
            
            for (DWORD i = 0; i < exportDir->NumberOfFunctions; i++) {
                if (functions[i] != 0) {
                    // RVA to file offset
                    uintptr_t rva = functions[i];
                    uintptr_t fileOffset = RVAToFileOffset(rva, ntHeader);
                    
                    // Registrar export
                    std::string name = GetExportName(data, names[i]);
                    exports[name] = fileOffset;
                }
            }
        }
    }
    
    void FindVTables(const std::vector<BYTE>& data) {
        // Procurar por vtables via RTTI ou padrões
        // Analisar .rdata section
    }
    
    void GenerateOffsetMap(const std::vector<BYTE>& data) {
        // Gerar mapa completo de offsets
        // Salvar para uso posterior
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Pattern Detection
```cpp
// VAC pattern scanning detection
class VAC_PatternDetector {
private:
    MemoryAccessDetector accessDetector;
    SignatureDetector sigDetector;
    BehavioralAnalyzer behaviorAnalyzer;
    
public:
    void Initialize() {
        accessDetector.Initialize();
        sigDetector.Initialize();
        behaviorAnalyzer.Initialize();
    }
    
    void OnMemoryAccess(HANDLE hProcess, uintptr_t address, SIZE_T size) {
        // Detectar acesso
        accessDetector.OnMemoryRead(hProcess, address, size);
        
        // Verificar signatures
        std::vector<BYTE> code = ReadMemory(hProcess, address, size);
        if (sigDetector.IsKnownScannerSignature(code)) {
            ReportPatternScanner();
        }
        
        // Análise comportamental
        float confidence = behaviorAnalyzer.AnalyzeBehavior(hProcess, GetRecentAccesses(hProcess));
        if (confidence > DETECTION_THRESHOLD) {
            ReportPatternScanner();
        }
    }
};
```

### BattlEye Advanced Detection
```cpp
// BE advanced pattern detection
void BE_DetectAdvancedPatterns() {
    // Monitor all memory operations
    MonitorMemoryOperations();
    
    // Analyze code patterns
    AnalyzeCodePatterns();
    
    // Detect obfuscated scanners
    DetectObfuscatedScanners();
}

void MonitorMemoryOperations() {
    // Hook all memory read functions
    // Track patterns and behaviors
}

void AnalyzeCodePatterns() {
    // Look for scanning algorithms
    // Detect Boyer-Moore, KMP, etc.
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | Básica |
| 2020-2024 | ⚠️ Médio risco | Access patterns |
| 2025-2026 | ⚠️ Alto risco | AI behavioral |

---

## 🎯 Lições Aprendidas

1. **Acessos São Monitorados**: Mesmo leituras pequenas são rastreadas.

2. **Signatures São Conhecidas**: Padrões comuns são facilmente detectados.

3. **Comportamento é Analisado**: Taxa de acesso e padrões comportamentais são monitorados.

4. **Análise Estática é Superior**: Encontrar offsets offline evita detecção.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#20]]
- [[Pre_computed_Offsets]]
- [[Symbol_Resolution]]
- [[Static_Analysis_Tools]]

---

*Pattern scanning tem risco moderado. Use offsets pré-calculados quando possível.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
