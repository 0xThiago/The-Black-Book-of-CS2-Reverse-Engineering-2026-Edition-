# Técnica 040 - Code Packing and Compression

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[DATABASE]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Anti-Analysis  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Code Packing and Compression** comprime e ofusca código executável, dificultando análise estática e reduzindo tamanho. Usado para proteger cheats contra engenharia reversa.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class CodePacker {
private:
    std::vector<BYTE> originalCode;
    std::vector<BYTE> compressedCode;
    std::vector<BYTE> packedCode;
    PACKER_CONFIG config;
    
public:
    CodePacker() {
        config.compressionLevel = 9; // Máxima compressão
        config.encryptionKey = GenerateRandomKey();
        config.usePolymorphism = true;
        config.antiDumpProtection = true;
    }
    
    void PackCode(PVOID codeAddress, SIZE_T codeSize) {
        // 1. Extrair código original
        ExtractOriginalCode(codeAddress, codeSize);
        
        // 2. Aplicar compressão
        CompressCode();
        
        // 3. Aplicar encriptação
        EncryptCode();
        
        // 4. Adicionar stub de descompressão
        AddDecompressionStub();
        
        // 5. Aplicar proteções anti-dump
        AddAntiDumpProtection();
        
        // 6. Gerar código final
        GeneratePackedCode();
    }
    
    void ExtractOriginalCode(PVOID address, SIZE_T size) {
        originalCode.resize(size);
        memcpy(originalCode.data(), address, size);
    }
    
    void CompressCode() {
        // Usar LZMA ou similar para compressão
        compressedCode = CompressLZMA(originalCode);
    }
    
    void EncryptCode() {
        // Encriptar código comprimido
        EncryptAES(compressedCode, config.encryptionKey);
    }
    
    void AddDecompressionStub() {
        // Criar stub que descomprime e executa
        packedCode.clear();
        
        // Adicionar código do stub
        AppendStubCode();
        
        // Adicionar dados comprimidos/encriptados
        AppendCompressedData();
        
        // Adicionar metadados
        AppendMetadata();
    }
    
    void AppendStubCode() {
        // Código assembly do stub
        const BYTE stubCode[] = {
            // Descompressão LZMA + decriptação AES + execução
            0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, // PUSH EBP, MOV EBP, ESP, SUB ESP, 10h
            // ... resto do stub ...
        };
        
        packedCode.insert(packedCode.end(), stubCode, stubCode + sizeof(stubCode));
    }
    
    void AppendCompressedData() {
        // Adicionar dados comprimidos
        packedCode.insert(packedCode.end(), compressedCode.begin(), compressedCode.end());
    }
    
    void AppendMetadata() {
        // Adicionar informações sobre compressão, tamanho original, etc.
        PACKER_METADATA metadata;
        metadata.originalSize = originalCode.size();
        metadata.compressedSize = compressedCode.size();
        metadata.compressionType = COMPRESSION_LZMA;
        metadata.encryptionType = ENCRYPTION_AES;
        metadata.key = config.encryptionKey;
        
        BYTE* metadataBytes = (BYTE*)&metadata;
        packedCode.insert(packedCode.end(), metadataBytes, metadataBytes + sizeof(metadata));
    }
    
    void AddAntiDumpProtection() {
        if (config.antiDumpProtection) {
            // Adicionar verificações anti-dump
            AddIntegrityChecks();
            AddAntiDebugChecks();
            AddTimeBombs();
        }
    }
    
    void AddIntegrityChecks() {
        // Verificar integridade do código
        // Se modificado, corromper execução
    }
    
    void AddAntiDebugChecks() {
        // Verificações básicas de debugger
    }
    
    void AddTimeBombs() {
        // Código que se ativa após certo tempo
    }
    
    void GeneratePackedCode() {
        // Código final pronto para execução
    }
    
    std::vector<BYTE> CompressLZMA(const std::vector<BYTE>& data) {
        // Implementação LZMA
        // Usar LZMA SDK ou similar
        return data; // Placeholder
    }
    
    void EncryptAES(std::vector<BYTE>& data, const std::string& key) {
        // Implementação AES
        // Usar Crypto++ ou similar
    }
    
    std::string GenerateRandomKey() {
        std::string key;
        for (int i = 0; i < 32; i++) { // 256-bit key
            key += (char)(rand() % 256);
        }
        return key;
    }
};
```

### Advanced Packing Techniques

```cpp
// Técnicas avançadas de packing
class AdvancedCodePacker : public CodePacker {
private:
    std::vector<POLYMORPHIC_LAYER> layers;
    std::vector<OBFUSCATION_TECHNIQUE> techniques;
    
public:
    AdvancedCodePacker() {
        InitializePolymorphicLayers();
        InitializeObfuscationTechniques();
    }
    
    void InitializePolymorphicLayers() {
        // Camadas polimórficas
        layers.push_back({LAYER_ENCRYPTION, "AES-256-CBC"});
        layers.push_back({LAYER_COMPRESSION, "LZMA2"});
        layers.push_back({LAYER_OBFUSCATION, "Control Flow Flattening"});
        layers.push_back({LAYER_POLYMORPHISM, "Dynamic Code Generation"});
    }
    
    void InitializeObfuscationTechniques() {
        techniques.push_back({TECHNIQUE_JUNK_CODE, "Add random instructions"});
        techniques.push_back({TECHNIQUE_OPAQUE_PREDICATES, "Add always-true conditions"});
        techniques.push_back({TECHNIQUE_STRING_ENCRYPTION, "Encrypt all strings"});
        techniques.push_back({TECHNIQUE_API_OBFUSCATION, "Hide API calls"});
    }
    
    void ApplyAdvancedPacking(PVOID codeAddress, SIZE_T codeSize) {
        // Aplicar camadas em ordem
        std::vector<BYTE> currentCode((BYTE*)codeAddress, (BYTE*)codeAddress + codeSize);
        
        for (const POLYMORPHIC_LAYER& layer : layers) {
            currentCode = ApplyLayer(currentCode, layer);
        }
        
        // Aplicar técnicas de ofuscação
        for (const OBFUSCATION_TECHNIQUE& tech : techniques) {
            currentCode = ApplyTechnique(currentCode, tech);
        }
        
        // Gerar executável final
        GenerateFinalExecutable(currentCode);
    }
    
    std::vector<BYTE> ApplyLayer(const std::vector<BYTE>& code, const POLYMORPHIC_LAYER& layer) {
        switch (layer.type) {
            case LAYER_ENCRYPTION:
                return ApplyEncryptionLayer(code, layer.parameters);
            case LAYER_COMPRESSION:
                return ApplyCompressionLayer(code, layer.parameters);
            case LAYER_OBFUSCATION:
                return ApplyObfuscationLayer(code, layer.parameters);
            case LAYER_POLYMORPHISM:
                return ApplyPolymorphismLayer(code, layer.parameters);
            default:
                return code;
        }
    }
    
    std::vector<BYTE> ApplyEncryptionLayer(const std::vector<BYTE>& code, const std::string& params) {
        // Aplicar encriptação
        std::vector<BYTE> encrypted = code;
        
        if (params == "AES-256-CBC") {
            EncryptAES256CBC(encrypted);
        } else if (params == "ChaCha20") {
            EncryptChaCha20(encrypted);
        }
        
        return encrypted;
    }
    
    std::vector<BYTE> ApplyCompressionLayer(const std::vector<BYTE>& code, const std::string& params) {
        // Aplicar compressão
        if (params == "LZMA2") {
            return CompressLZMA2(code);
        } else if (params == "Zstandard") {
            return CompressZstd(code);
        }
        
        return code;
    }
    
    std::vector<BYTE> ApplyObfuscationLayer(const std::vector<BYTE>& code, const std::string& params) {
        // Aplicar ofuscação
        std::vector<BYTE> obfuscated = code;
        
        if (params == "Control Flow Flattening") {
            obfuscated = ApplyControlFlowFlattening(obfuscated);
        } else if (params == "Instruction Substitution") {
            obfuscated = ApplyInstructionSubstitution(obfuscated);
        }
        
        return obfuscated;
    }
    
    std::vector<BYTE> ApplyPolymorphismLayer(const std::vector<BYTE>& code, const std::string& params) {
        // Aplicar polimorfismo
        if (params == "Dynamic Code Generation") {
            return GenerateDynamicCode(code);
        }
        
        return code;
    }
    
    std::vector<BYTE> ApplyTechnique(const std::vector<BYTE>& code, const OBFUSCATION_TECHNIQUE& tech) {
        switch (tech.type) {
            case TECHNIQUE_JUNK_CODE:
                return AddJunkCode(code);
            case TECHNIQUE_OPAQUE_PREDICATES:
                return AddOpaquePredicates(code);
            case TECHNIQUE_STRING_ENCRYPTION:
                return EncryptStrings(code);
            case TECHNIQUE_API_OBFUSCATION:
                return ObfuscateAPICalls(code);
            default:
                return code;
        }
    }
    
    std::vector<BYTE> AddJunkCode(const std::vector<BYTE>& code) {
        std::vector<BYTE> result;
        
        for (size_t i = 0; i < code.size(); i++) {
            result.push_back(code[i]);
            
            // Adicionar junk code aleatoriamente
            if (rand() % 10 == 0) {
                std::vector<BYTE> junk = GenerateJunkCode();
                result.insert(result.end(), junk.begin(), junk.end());
            }
        }
        
        return result;
    }
    
    std::vector<BYTE> GenerateJunkCode() {
        // Gerar instruções NOP ou equivalentes
        std::vector<BYTE> junk;
        
        int junkSize = rand() % 10 + 1;
        for (int i = 0; i < junkSize; i++) {
            junk.push_back(0x90); // NOP
        }
        
        return junk;
    }
    
    std::vector<BYTE> AddOpaquePredicates(const std::vector<BYTE>& code) {
        // Adicionar condições sempre verdadeiras
        // Ex: if (IsPrime(17)) { ... } else { unreachable code }
        return code; // Placeholder
    }
    
    std::vector<BYTE> EncryptStrings(const std::vector<BYTE>& code) {
        // Encontrar e encriptar strings no código
        return code; // Placeholder
    }
    
    std::vector<BYTE> ObfuscateAPICalls(const std::vector<BYTE>& code) {
        // Ofuscar chamadas de API
        return code; // Placeholder
    }
    
    std::vector<BYTE> ApplyControlFlowFlattening(const std::vector<BYTE>& code) {
        // Transformar fluxo de controle em switch statement
        return code; // Placeholder
    }
    
    std::vector<BYTE> ApplyInstructionSubstitution(const std::vector<BYTE>& code) {
        // Substituir instruções por equivalentes
        return code; // Placeholder
    }
    
    std::vector<BYTE> GenerateDynamicCode(const std::vector<BYTE>& code) {
        // Gerar código dinamicamente em runtime
        return code; // Placeholder
    }
    
    void GenerateFinalExecutable(const std::vector<BYTE>& packedCode) {
        // Criar executável final
        CreatePEFile(packedCode);
    }
    
    void CreatePEFile(const std::vector<BYTE>& code) {
        // Criar estrutura PE
        // Adicionar headers, seções, etc.
    }
    
    // Implementações de criptografia/compressão
    void EncryptAES256CBC(std::vector<BYTE>& data) { /* AES implementation */ }
    void EncryptChaCha20(std::vector<BYTE>& data) { /* ChaCha20 implementation */ }
    std::vector<BYTE> CompressLZMA2(const std::vector<BYTE>& data) { return data; }
    std::vector<BYTE> CompressZstd(const std::vector<BYTE>& data) { return data; }
};
```

### Por que é Detectado

> [!WARNING]
> **Packing deixa rastros através de anomalias na estrutura PE e comportamento suspeito**

#### 1. PE Structure Analysis
```cpp
// Análise de estrutura PE
class PEStructureAnalyzer {
private:
    std::vector<PE_ANOMALY> knownAnomalies;
    
public:
    void AnalyzePEFile(const char* filePath) {
        // Carregar arquivo PE
        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, 
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        
        if (hFile == INVALID_HANDLE_VALUE) return;
        
        // Mapear arquivo
        HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        PVOID pMappedFile = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        
        // Analisar estrutura
        AnalyzePEStructure(pMappedFile);
        
        // Limpar
        UnmapViewOfFile(pMappedFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
    }
    
    void AnalyzePEStructure(PVOID pPEFile) {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pPEFile;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pPEFile + pDosHeader->e_lfanew);
        
        // Verificar anomalias
        CheckSectionAnomalies(pNtHeaders);
        CheckImportAnomalies(pNtHeaders);
        CheckResourceAnomalies(pNtHeaders);
        CheckEntryPointAnomalies(pNtHeaders);
    }
    
    void CheckSectionAnomalies(PIMAGE_NT_HEADERS pNtHeaders) {
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            // Verificar seções suspeitas
            if (IsSuspiciousSectionName((char*)pSection[i].Name)) {
                ReportAnomaly("Suspicious section name: " + std::string((char*)pSection[i].Name));
            }
            
            // Verificar características de seção
            if (HasSuspiciousSectionCharacteristics(pSection[i].Characteristics)) {
                ReportAnomaly("Suspicious section characteristics");
            }
            
            // Verificar entropia alta (possível compressão/encriptação)
            if (CalculateSectionEntropy(pNtHeaders, &pSection[i]) > 7.0) {
                ReportAnomaly("High entropy section (possible compression/encryption)");
            }
        }
    }
    
    void CheckImportAnomalies(PIMAGE_NT_HEADERS pNtHeaders) {
        // Verificar imports suspeitos
        PIMAGE_DATA_DIRECTORY pImportDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        
        if (pImportDir->Size == 0) {
            ReportAnomaly("No import directory (possible packed file)");
        }
        
        // Verificar imports de packer
        if (HasPackerImports(pNtHeaders)) {
            ReportAnomaly("Packer-related imports detected");
        }
    }
    
    void CheckResourceAnomalies(PIMAGE_NT_HEADERS pNtHeaders) {
        // Verificar recursos suspeitos
        PIMAGE_DATA_DIRECTORY pResourceDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
        
        if (pResourceDir->Size == 0) {
            ReportAnomaly("No resource directory (possible packed file)");
        }
    }
    
    void CheckEntryPointAnomalies(PIMAGE_NT_HEADERS pNtHeaders) {
        // Verificar entry point suspeito
        DWORD entryPoint = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
        
        if (entryPoint == 0) {
            ReportAnomaly("Invalid entry point");
        }
        
        // Verificar se entry point está em seção suspeita
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            if (entryPoint >= pSection[i].VirtualAddress && 
                entryPoint < pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize) {
                
                if (IsSuspiciousSectionName((char*)pSection[i].Name)) {
                    ReportAnomaly("Entry point in suspicious section");
                }
                break;
            }
        }
    }
    
    bool IsSuspiciousSectionName(const char* name) {
        const char* suspiciousNames[] = {
            ".packed", ".compressed", ".encrypted",
            ".UPX0", ".UPX1", ".UPX2", // UPX sections
            ".aspack", ".nsp0", ".nsp1", ".nsp2" // Aspack sections
        };
        
        for (const char* suspicious : suspiciousNames) {
            if (strstr(name, suspicious) != NULL) {
                return true;
            }
        }
        
        return false;
    }
    
    bool HasSuspiciousSectionCharacteristics(DWORD characteristics) {
        // Verificar características suspeitas
        return (characteristics & IMAGE_SCN_MEM_EXECUTE) &&
               (characteristics & IMAGE_SCN_MEM_WRITE) &&
               !(characteristics & IMAGE_SCN_MEM_READ);
    }
    
    double CalculateSectionEntropy(PIMAGE_NT_HEADERS pNtHeaders, PIMAGE_SECTION_HEADER pSection) {
        // Calcular entropia de Shannon
        PBYTE pSectionData = (PBYTE)pNtHeaders + pSection->PointerToRawData;
        DWORD sectionSize = pSection->SizeOfRawData;
        
        if (sectionSize == 0) return 0.0;
        
        std::map<BYTE, int> frequency;
        for (DWORD i = 0; i < sectionSize; i++) {
            frequency[pSectionData[i]]++;
        }
        
        double entropy = 0.0;
        for (const auto& pair : frequency) {
            double p = (double)pair.second / sectionSize;
            entropy -= p * log2(p);
        }
        
        return entropy;
    }
    
    bool HasPackerImports(PIMAGE_NT_HEADERS pNtHeaders) {
        // Verificar imports de packers conhecidos
        return false; // Placeholder
    }
    
    void ReportAnomaly(const std::string& description) {
        // Reportar anomalia detectada
        std::cout << "PE Anomaly: " << description << std::endl;
    }
};
```

#### 2. Runtime Behavior Analysis
```cpp
// Análise comportamental em runtime
class RuntimeBehaviorAnalyzer {
private:
    std::map<DWORD, PROCESS_BEHAVIOR> processBehaviors;
    
public:
    void MonitorProcess(DWORD processId) {
        // Registrar comportamento inicial
        RegisterInitialBehavior(processId);
        
        // Monitorar mudanças
        StartRuntimeMonitoring(processId);
    }
    
    void RegisterInitialBehavior(DWORD processId) {
        PROCESS_BEHAVIOR behavior;
        
        // Registrar módulos iniciais
        behavior.initialModules = GetLoadedModules(processId);
        
        // Registrar seções de memória iniciais
        behavior.initialMemorySections = GetMemorySections(processId);
        
        processBehaviors[processId] = behavior;
    }
    
    void StartRuntimeMonitoring(DWORD processId) {
        std::thread([this, processId]() {
            while (true) {
                CheckRuntimeAnomalies(processId);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }).detach();
    }
    
    void CheckRuntimeAnomalies(DWORD processId) {
        if (processBehaviors.find(processId) == processBehaviors.end()) return;
        
        PROCESS_BEHAVIOR& behavior = processBehaviors[processId];
        
        // Verificar unpacking
        if (HasUnpackingBehavior(processId, behavior)) {
            ReportUnpackingDetected(processId);
        }
        
        // Verificar alocação suspeita de memória
        if (HasSuspiciousMemoryAllocation(processId)) {
            ReportSuspiciousMemoryAllocation(processId);
        }
        
        // Verificar mudanças na estrutura PE
        if (HasPEStructureChanges(processId, behavior)) {
            ReportPEStructureChanges(processId);
        }
    }
    
    bool HasUnpackingBehavior(DWORD processId, const PROCESS_BEHAVIOR& behavior) {
        // Verificar sinais de unpacking
        return HasMemoryDecompression(processId) ||
               HasDynamicCodeGeneration(processId) ||
               HasImportResolution(processId);
    }
    
    bool HasMemoryDecompression(DWORD processId) {
        // Verificar descompressão na memória
        // Monitorar chamadas para APIs de compressão
        return false; // Placeholder
    }
    
    bool HasDynamicCodeGeneration(DWORD processId) {
        // Verificar geração dinâmica de código
        // Monitorar VirtualAlloc + memcpy patterns
        return false; // Placeholder
    }
    
    bool HasImportResolution(DWORD processId) {
        // Verificar resolução dinâmica de imports
        return false; // Placeholder
    }
    
    bool HasSuspiciousMemoryAllocation(DWORD processId) {
        // Verificar alocações grandes de memória executável
        return false; // Placeholder
    }
    
    bool HasPEStructureChanges(DWORD processId, const PROCESS_BEHAVIOR& behavior) {
        // Verificar mudanças na estrutura PE em memória
        return false; // Placeholder
    }
    
    std::vector<HMODULE> GetLoadedModules(DWORD processId) {
        // Obter módulos carregados
        return std::vector<HMODULE>(); // Placeholder
    }
    
    std::vector<MEMORY_SECTION> GetMemorySections(DWORD processId) {
        // Obter seções de memória
        return std::vector<MEMORY_SECTION>(); // Placeholder
    }
    
    void ReportUnpackingDetected(DWORD processId) {
        // Reportar detecção de unpacking
    }
    
    void ReportSuspiciousMemoryAllocation(DWORD processId) {
        // Reportar alocação suspeita
    }
    
    void ReportPEStructureChanges(DWORD processId) {
        // Reportar mudanças na estrutura PE
    }
};
```

#### 3. Entropy Analysis
```cpp
// Análise de entropia
class EntropyAnalyzer {
public:
    void AnalyzeFileEntropy(const char* filePath) {
        // Calcular entropia do arquivo
        double fileEntropy = CalculateFileEntropy(filePath);
        
        if (fileEntropy > 7.0) {
            ReportHighEntropy("File entropy too high: " + std::to_string(fileEntropy));
        }
        
        // Analisar entropia por seção
        AnalyzeSectionEntropy(filePath);
    }
    
    double CalculateFileEntropy(const char* filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return 0.0;
        
        std::map<BYTE, int> frequency;
        char byte;
        int totalBytes = 0;
        
        while (file.get(byte)) {
            frequency[(BYTE)byte]++;
            totalBytes++;
        }
        
        double entropy = 0.0;
        for (const auto& pair : frequency) {
            double p = (double)pair.second / totalBytes;
            entropy -= p * log2(p);
        }
        
        return entropy;
    }
    
    void AnalyzeSectionEntropy(const char* filePath) {
        // Mapear arquivo e analisar entropia por seção
        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        
        if (hFile == INVALID_HANDLE_VALUE) return;
        
        HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        PVOID pMappedFile = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        
        // Analisar PE sections
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMappedFile;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pMappedFile + pDosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            double sectionEntropy = CalculateSectionEntropy(pMappedFile, &pSection[i]);
            
            if (sectionEntropy > 7.5) {
                ReportHighEntropy("Section " + std::string((char*)pSection[i].Name) + 
                                " entropy: " + std::to_string(sectionEntropy));
            }
        }
        
        UnmapViewOfFile(pMappedFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
    }
    
    double CalculateSectionEntropy(PVOID pMappedFile, PIMAGE_SECTION_HEADER pSection) {
        PBYTE pSectionData = (PBYTE)pMappedFile + pSection->PointerToRawData;
        DWORD sectionSize = pSection->SizeOfRawData;
        
        if (sectionSize == 0) return 0.0;
        
        std::map<BYTE, int> frequency;
        for (DWORD i = 0; i < sectionSize; i++) {
            frequency[pSectionData[i]]++;
        }
        
        double entropy = 0.0;
        for (const auto& pair : frequency) {
            double p = (double)pair.second / sectionSize;
            entropy -= p * log2(p);
        }
        
        return entropy;
    }
    
    void ReportHighEntropy(const std::string& message) {
        // Reportar entropia alta
        std::cout << "High Entropy: " << message << std::endl;
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | PE structure analysis | < 30s | 90% |
| VAC Live | Runtime unpacking detection | Imediato | 85% |
| BattlEye | Entropy analysis | < 1 min | 95% |
| Faceit AC | Behavioral analysis | < 30s | 80% |

---

## 🔄 Alternativas Seguras

### 1. Custom Packers
```cpp
// ✅ Packers customizados
class CustomPacker {
private:
    std::unique_ptr<CompressionAlgorithm> compressor;
    std::unique_ptr<EncryptionAlgorithm> encryptor;
    std::unique_ptr<ObfuscationEngine> obfuscator;
    
public:
    CustomPacker() {
        // Usar algoritmos customizados
        compressor = std::make_unique<CustomLZMA>();
        encryptor = std::make_unique<CustomAES>();
        obfuscator = std::make_unique<CustomObfuscator>();
    }
    
    void PackCode(PVOID codeAddress, SIZE_T codeSize) {
        // 1. Aplicar ofuscação primeiro
        std::vector<BYTE> obfuscatedCode = obfuscator->Obfuscate(codeAddress, codeSize);
        
        // 2. Comprimir
        std::vector<BYTE> compressedCode = compressor->Compress(obfuscatedCode);
        
        // 3. Encriptar
        std::vector<BYTE> encryptedCode = encryptor->Encrypt(compressedCode);
        
        // 4. Criar stub customizado
        std::vector<BYTE> finalCode = CreateCustomStub(encryptedCode);
        
        // 5. Salvar
        SavePackedFile(finalCode);
    }
    
    std::vector<BYTE> CreateCustomStub(const std::vector<BYTE>& payload) {
        // Criar stub único para cada packing
        std::vector<BYTE> stub;
        
        // Adicionar código de descompressão customizado
        AppendCustomDecompressionCode(stub);
        
        // Adicionar payload
        stub.insert(stub.end(), payload.begin(), payload.end());
        
        // Adicionar metadados customizados
        AppendCustomMetadata(stub);
        
        return stub;
    }
    
    void AppendCustomDecompressionCode(std::vector<BYTE>& stub) {
        // Código assembly customizado para descompressão
        // Diferente para cada versão
    }
    
    void AppendCustomMetadata(std::vector<BYTE>& stub) {
        // Metadados customizados, não padronizados
    }
    
    void SavePackedFile(const std::vector<BYTE>& code) {
        // Salvar como executável
    }
};
```

### 2. Runtime Code Generation
```cpp
// ✅ Geração de código em runtime
class RuntimeCodeGenerator {
private:
    std::vector<CODE_TEMPLATE> templates;
    std::map<std::string, FUNCTION_GENERATOR> generators;
    
public:
    RuntimeCodeGenerator() {
        InitializeTemplates();
        InitializeGenerators();
    }
    
    void InitializeTemplates() {
        // Templates para diferentes funções
        templates.push_back({TEMPLATE_HOOK, "Hook template"});
        templates.push_back({TEMPLATE_MEMORY, "Memory manipulation template"});
        templates.push_back({TEMPLATE_ANTIDEBUG, "Anti-debug template"});
    }
    
    void InitializeGenerators() {
        // Geradores para funções específicas
        generators["CreateHook"] = &RuntimeCodeGenerator::GenerateHookFunction;
        generators["MemoryScan"] = &RuntimeCodeGenerator::GenerateMemoryScanFunction;
        generators["AntiDebugCheck"] = &RuntimeCodeGenerator::GenerateAntiDebugFunction;
    }
    
    PVOID GenerateFunction(const std::string& functionName, const std::vector<std::string>& parameters) {
        // Gerar função em runtime
        if (generators.find(functionName) != generators.end()) {
            return generators[functionName](parameters);
        }
        
        return nullptr;
    }
    
    PVOID GenerateHookFunction(const std::vector<std::string>& params) {
        // Gerar código para hook
        std::vector<BYTE> code;
        
        // Adicionar prólogo
        AppendPrologue(code);
        
        // Adicionar lógica de hook
        AppendHookLogic(code, params);
        
        // Adicionar epílogo
        AppendEpilogue(code);
        
        // Alocar memória executável
        PVOID pCode = AllocateExecutableMemory(code.size());
        memcpy(pCode, code.data(), code.size());
        
        return pCode;
    }
    
    PVOID GenerateMemoryScanFunction(const std::vector<std::string>& params) {
        // Gerar código para scan de memória
        std::vector<BYTE> code;
        
        AppendPrologue(code);
        AppendMemoryScanLogic(code, params);
        AppendEpilogue(code);
        
        PVOID pCode = AllocateExecutableMemory(code.size());
        memcpy(pCode, code.data(), code.size());
        
        return pCode;
    }
    
    PVOID GenerateAntiDebugFunction(const std::vector<std::string>& params) {
        // Gerar código para verificações anti-debug
        std::vector<BYTE> code;
        
        AppendPrologue(code);
        AppendAntiDebugLogic(code, params);
        AppendEpilogue(code);
        
        PVOID pCode = AllocateExecutableMemory(code.size());
        memcpy(pCode, code.data(), code.size());
        
        return pCode;
    }
    
    void AppendPrologue(std::vector<BYTE>& code) {
        // PUSH EBP, MOV EBP, ESP
        code.push_back(0x55);
        code.push_back(0x8B);
        code.push_back(0xEC);
    }
    
    void AppendEpilogue(std::vector<BYTE>& code) {
        // MOV ESP, EBP, POP EBP, RET
        code.push_back(0x8B);
        code.push_back(0xE5);
        code.push_back(0x5D);
        code.push_back(0xC3);
    }
    
    void AppendHookLogic(std::vector<BYTE>& code, const std::vector<std::string>& params) {
        // Lógica específica do hook
        // Gerada dinamicamente baseada nos parâmetros
    }
    
    void AppendMemoryScanLogic(std::vector<BYTE>& code, const std::vector<std::string>& params) {
        // Lógica de scan de memória
    }
    
    void AppendAntiDebugLogic(std::vector<BYTE>& code, const std::vector<std::string>& params) {
        // Lógica anti-debug
    }
    
    PVOID AllocateExecutableMemory(SIZE_T size) {
        return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    
    void ExecuteGeneratedFunction(PVOID pFunction, const std::vector<PVOID>& args) {
        // Executar função gerada
        // Usar std::function ou similar
    }
};
```

### 3. Just-In-Time Compilation
```cpp
// ✅ Compilação JIT
class JITCompiler {
private:
    std::unique_ptr<CompilerBackend> backend;
    std::vector<OPTIMIZATION_PASS> passes;
    
public:
    JITCompiler() {
        // Inicializar backend (LLVM, GCC JIT, etc.)
        backend = std::make_unique<LLVMBackend>();
        
        // Inicializar passes de otimização
        InitializeOptimizationPasses();
    }
    
    void InitializeOptimizationPasses() {
        passes.push_back({PASS_OBFUSCATION, "Code obfuscation"});
        passes.push_back({PASS_INLINE, "Function inlining"});
        passes.push_back({PASS_DEAD_CODE, "Dead code elimination"});
        passes.push_back({PASS_CONSTANT_FOLDING, "Constant folding"});
    }
    
    PVOID CompileToNative(const std::string& sourceCode) {
        // 1. Parse do código fonte
        AST* ast = ParseSourceCode(sourceCode);
        
        // 2. Aplicar otimizações
        for (const OPTIMIZATION_PASS& pass : passes) {
            ast = ApplyOptimizationPass(ast, pass);
        }
        
        // 3. Gerar código nativo
        std::vector<BYTE> nativeCode = backend->CompileToNative(ast);
        
        // 4. Aplicar ofuscação final
        nativeCode = ApplyFinalObfuscation(nativeCode);
        
        // 5. Alocar e retornar
        PVOID pCode = AllocateExecutableMemory(nativeCode.size());
        memcpy(pCode, nativeCode.data(), nativeCode.size());
        
        return pCode;
    }
    
    AST* ParseSourceCode(const std::string& source) {
        // Parser para código C/C++
        return nullptr; // Placeholder
    }
    
    AST* ApplyOptimizationPass(AST* ast, const OPTIMIZATION_PASS& pass) {
        // Aplicar pass de otimização
        return ast; // Placeholder
    }
    
    std::vector<BYTE> ApplyFinalObfuscation(const std::vector<BYTE>& code) {
        // Ofuscação final do código nativo
        return code; // Placeholder
    }
    
    PVOID AllocateExecutableMemory(SIZE_T size) {
        return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    
    void ExecuteCompiledCode(PVOID pCode, const std::vector<PVOID>& args) {
        // Executar código compilado
        typedef void (*CompiledFunction)(...);
        CompiledFunction func = (CompiledFunction)pCode;
        
        // Chamar com argumentos
        // func(args...);
    }
};
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ⚠️ Risco | Basic signature |
| 2015-2020 | ⚠️ Médio risco | Entropy analysis |
| 2020-2024 | ⚠️ Alto risco | Runtime detection |
| 2025-2026 | ⚠️ Muito alto risco | Advanced analysis |

---

## 🎯 Lições Aprendidas

1. **Entropia é Rastreada**: Código comprimido tem entropia alta.

2. **Estrutura PE é Analisada**: Anomalias na estrutura são detectadas.

3. **Comportamento é Monitorado**: Unpacking em runtime é identificado.

4. **Customização é Melhor**: Packers customizados são mais stealth.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#40]]
- [[Code_Obfuscation]]
- [[Runtime_Code_Generation]]
- [[JIT_Compilation]]

---

*Code packing tem risco moderado. Considere custom packers para mais stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
