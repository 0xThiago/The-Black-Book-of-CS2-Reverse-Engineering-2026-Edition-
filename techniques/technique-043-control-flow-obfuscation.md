# 📖 Técnica 043: Control Flow Obfuscation

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 043: Control Flow Obfuscation]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Anti-Analysis  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Control Flow Obfuscation** modifica o fluxo de controle do programa para dificultar análise estática e debugging, usando técnicas como flattening, opaque predicates e código morto para confundir engenheiros reversos.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class ControlFlowObfuscator {
private:
    std::vector<OBFUSCATION_TECHNIQUE> techniques;
    CONTROL_FLOW_GRAPH cfg;
    
public:
    ControlFlowObfuscator() {
        InitializeTechniques();
    }
    
    void InitializeTechniques() {
        techniques.push_back({TECHNIQUE_CONTROL_FLOW_FLATTENING, "Control flow flattening"});
        techniques.push_back({TECHNIQUE_OPAQUE_PREDICATES, "Opaque predicates insertion"});
        techniques.push_back({TECHNIQUE_JUNK_CODE, "Junk code insertion"});
        techniques.push_back({TECHNIQUE_CODE_REORDERING, "Code reordering"});
        techniques.push_back({TECHNIQUE_CONDITIONAL_OBFUSCATION, "Conditional obfuscation"});
    }
    
    void ObfuscateControlFlow(PVOID functionAddress, SIZE_T functionSize) {
        // Construir CFG da função
        BuildCFG(functionAddress, functionSize);
        
        // Aplicar técnicas de ofuscação
        for (const OBFUSCATION_TECHNIQUE& tech : techniques) {
            ApplyTechnique(tech);
        }
        
        // Gerar código ofuscado
        GenerateObfuscatedCode();
    }
    
    void BuildCFG(PVOID functionAddress, SIZE_T functionSize) {
        // Construir Control Flow Graph
        cfg.functionAddress = functionAddress;
        cfg.functionSize = functionSize;
        
        // Identificar blocos básicos
        IdentifyBasicBlocks();
        
        // Construir grafo de fluxo
        BuildFlowGraph();
    }
    
    void IdentifyBasicBlocks() {
        BYTE* code = (BYTE*)cfg.functionAddress;
        
        BASIC_BLOCK currentBlock;
        currentBlock.startAddress = code;
        
        for (SIZE_T i = 0; i < cfg.functionSize; ) {
            // Analisar instrução
            INSTRUCTION_INFO inst = DisassembleInstruction(&code[i]);
            
            // Verificar se é fim de bloco
            if (IsBlockEndInstruction(inst)) {
                currentBlock.endAddress = &code[i] + inst.length;
                currentBlock.instructions.push_back(inst);
                cfg.basicBlocks.push_back(currentBlock);
                
                // Iniciar novo bloco
                if (i + inst.length < cfg.functionSize) {
                    currentBlock = BASIC_BLOCK();
                    currentBlock.startAddress = &code[i + inst.length];
                }
            } else {
                currentBlock.instructions.push_back(inst);
            }
            
            i += inst.length;
        }
    }
    
    void BuildFlowGraph() {
        // Construir arestas do grafo
        for (size_t i = 0; i < cfg.basicBlocks.size(); i++) {
            BASIC_BLOCK& block = cfg.basicBlocks[i];
            
            // Analisar última instrução para determinar sucessores
            if (!block.instructions.empty()) {
                const INSTRUCTION_INFO& lastInst = block.instructions.back();
                
                if (IsConditionalJump(lastInst)) {
                    // Jump condicional - dois sucessores
                    PVOID target1 = CalculateJumpTarget(lastInst, block.startAddress);
                    PVOID target2 = GetFallThroughAddress(block);
                    
                    AddEdge(i, FindBlockIndex(target1));
                    AddEdge(i, FindBlockIndex(target2));
                } else if (IsUnconditionalJump(lastInst)) {
                    // Jump incondicional - um sucessor
                    PVOID target = CalculateJumpTarget(lastInst, block.startAddress);
                    AddEdge(i, FindBlockIndex(target));
                } else if (IsReturn(lastInst)) {
                    // Retorno - nenhum sucessor
                } else {
                    // Fall through
                    if (i + 1 < cfg.basicBlocks.size()) {
                        AddEdge(i, i + 1);
                    }
                }
            }
        }
    }
    
    void ApplyTechnique(const OBFUSCATION_TECHNIQUE& tech) {
        switch (tech.type) {
            case TECHNIQUE_CONTROL_FLOW_FLATTENING:
                ApplyControlFlowFlattening();
                break;
            case TECHNIQUE_OPAQUE_PREDICATES:
                ApplyOpaquePredicates();
                break;
            case TECHNIQUE_JUNK_CODE:
                ApplyJunkCode();
                break;
            case TECHNIQUE_CODE_REORDERING:
                ApplyCodeReordering();
                break;
            case TECHNIQUE_CONDITIONAL_OBFUSCATION:
                ApplyConditionalObfuscation();
                break;
        }
    }
    
    void ApplyControlFlowFlattening() {
        // Transformar estrutura em switch statement
        // Todos os blocos se tornam cases de um switch
        
        // Adicionar variável de estado
        cfg.stateVariable = AddStateVariable();
        
        // Transformar blocos
        for (size_t i = 0; i < cfg.basicBlocks.size(); i++) {
            FlattenBlock(cfg.basicBlocks[i], i);
        }
        
        // Adicionar dispatcher
        AddDispatcher();
    }
    
    void FlattenBlock(BASIC_BLOCK& block, size_t blockIndex) {
        // Modificar bloco para atualizar estado e continuar
        std::vector<BYTE> newCode;
        
        // Código original do bloco
        for (const INSTRUCTION_INFO& inst : block.instructions) {
            // Adicionar instrução (simplificado)
            // newCode.insert(newCode.end(), inst.bytes, inst.bytes + inst.length);
        }
        
        // Atualizar variável de estado
        AddStateUpdate(newCode, GetNextState(blockIndex));
        
        // Adicionar break/continue
        AddControlFlowBreak(newCode);
        
        block.flattenedCode = newCode;
        block.isFlattened = true;
    }
    
    void AddDispatcher() {
        // Adicionar loop com switch
        std::vector<BYTE> dispatcherCode;
        
        // while (true) {
        AddWhileLoop(dispatcherCode);
        
        // switch (state) {
        AddSwitchStatement(dispatcherCode);
        
        // cases para cada bloco
        for (size_t i = 0; i < cfg.basicBlocks.size(); i++) {
            AddCase(dispatcherCode, i, cfg.basicBlocks[i]);
        }
        
        // }
        AddSwitchEnd(dispatcherCode);
        
        // }
        AddWhileEnd(dispatcherCode);
        
        cfg.dispatcherCode = dispatcherCode;
    }
    
    void ApplyOpaquePredicates() {
        // Adicionar condições sempre verdadeiras/falsas
        for (BASIC_BLOCK& block : cfg.basicBlocks) {
            if (ShouldAddOpaquePredicate(block)) {
                AddOpaquePredicate(block);
            }
        }
    }
    
    void AddOpaquePredicate(BASIC_BLOCK& block) {
        // Inserir predicado opaco
        OPAQUE_PREDICATE pred = GenerateOpaquePredicate();
        
        // Inserir no início do bloco
        block.opaquePredicates.push_back(pred);
    }
    
    OPAQUE_PREDICATE GenerateOpaquePredicate() {
        OPAQUE_PREDICATE pred;
        
        // Exemplo: if (x * x - x * x == 0) - sempre true
        pred.condition = "x * x - x * x == 0";
        pred.alwaysTrue = true;
        
        // Ou: if ((x & 1) == 0 && (x & 1) == 1) - sempre false
        // pred.condition = "(x & 1) == 0 && (x & 1) == 1";
        // pred.alwaysTrue = false;
        
        return pred;
    }
    
    void ApplyJunkCode() {
        // Adicionar código morto
        for (BASIC_BLOCK& block : cfg.basicBlocks) {
            AddJunkInstructions(block);
        }
    }
    
    void AddJunkInstructions(BASIC_BLOCK& block) {
        // Adicionar instruções NOP, XCHG EAX,EAX, etc.
        std::vector<INSTRUCTION_INFO> junkInstructions;
        
        int junkCount = rand() % 5 + 1;
        for (int i = 0; i < junkCount; i++) {
            junkInstructions.push_back(GenerateJunkInstruction());
        }
        
        // Inserir em posições aleatórias
        InsertJunkAtRandomPositions(block, junkInstructions);
    }
    
    INSTRUCTION_INFO GenerateJunkInstruction() {
        INSTRUCTION_INFO inst;
        
        // NOP
        inst.bytes[0] = 0x90;
        inst.length = 1;
        strcpy(inst.mnemonic, "NOP");
        
        return inst;
    }
    
    void ApplyCodeReordering() {
        // Reordenar blocos básicos
        std::random_shuffle(cfg.basicBlocks.begin(), cfg.basicBlocks.end());
        
        // Atualizar índices e arestas
        UpdateBlockIndices();
        UpdateFlowEdges();
    }
    
    void ApplyConditionalObfuscation() {
        // Ofuscar condições
        for (BASIC_BLOCK& block : cfg.basicBlocks) {
            ObfuscateConditions(block);
        }
    }
    
    void ObfuscateConditions(BASIC_BLOCK& block) {
        // Transformar if (x == 5) em if ((x ^ key) == (5 ^ key))
        for (CONDITION& cond : block.conditions) {
            ObfuscateCondition(cond);
        }
    }
    
    void ObfuscateCondition(CONDITION& cond) {
        // Aplicar transformação XOR
        uint32_t key = GenerateRandomKey();
        
        cond.leftOperand = "(" + cond.leftOperand + " ^ " + std::to_string(key) + ")";
        cond.rightOperand = "(" + cond.rightOperand + " ^ " + std::to_string(key) + ")";
    }
    
    void GenerateObfuscatedCode() {
        // Combinar todos os componentes em código final
        cfg.obfuscatedCode.clear();
        
        // Adicionar dispatcher se flattening foi aplicado
        if (cfg.isFlattened) {
            cfg.obfuscatedCode.insert(cfg.obfuscatedCode.end(), 
                                    cfg.dispatcherCode.begin(), 
                                    cfg.dispatcherCode.end());
        }
        
        // Adicionar blocos ofuscados
        for (const BASIC_BLOCK& block : cfg.basicBlocks) {
            if (block.isFlattened) {
                cfg.obfuscatedCode.insert(cfg.obfuscatedCode.end(),
                                        block.flattenedCode.begin(),
                                        block.flattenedCode.end());
            }
        }
    }
    
    // Utility functions
    INSTRUCTION_INFO DisassembleInstruction(BYTE* code) {
        INSTRUCTION_INFO inst;
        // Implementar disassembler simples ou usar biblioteca
        return inst;
    }
    
    bool IsBlockEndInstruction(const INSTRUCTION_INFO& inst) {
        return IsConditionalJump(inst) || IsUnconditionalJump(inst) || 
               IsReturn(inst) || IsCall(inst);
    }
    
    bool IsConditionalJump(const INSTRUCTION_INFO& inst) {
        // JNZ, JZ, JB, etc.
        return strstr(inst.mnemonic, "J") != NULL && 
               strcmp(inst.mnemonic, "JMP") != 0;
    }
    
    bool IsUnconditionalJump(const INSTRUCTION_INFO& inst) {
        return strcmp(inst.mnemonic, "JMP") == 0;
    }
    
    bool IsReturn(const INSTRUCTION_INFO& inst) {
        return strcmp(inst.mnemonic, "RET") == 0;
    }
    
    bool IsCall(const INSTRUCTION_INFO& inst) {
        return strcmp(inst.mnemonic, "CALL") == 0;
    }
    
    PVOID CalculateJumpTarget(const INSTRUCTION_INFO& inst, PVOID currentAddress) {
        // Calcular endereço alvo do jump
        return nullptr; // Placeholder
    }
    
    PVOID GetFallThroughAddress(const BASIC_BLOCK& block) {
        // Calcular endereço de fall-through
        return (PVOID)((uintptr_t)block.endAddress);
    }
    
    size_t FindBlockIndex(PVOID address) {
        for (size_t i = 0; i < cfg.basicBlocks.size(); i++) {
            if (cfg.basicBlocks[i].startAddress == address) {
                return i;
            }
        }
        return -1;
    }
    
    void AddEdge(size_t from, size_t to) {
        cfg.edges.push_back({from, to});
    }
    
    STATE_VARIABLE AddStateVariable() {
        STATE_VARIABLE var;
        var.name = "state";
        var.type = "int";
        var.initialValue = 0;
        return var;
    }
    
    int GetNextState(size_t currentBlockIndex) {
        // Lógica para determinar próximo estado
        return currentBlockIndex + 1;
    }
    
    void AddStateUpdate(std::vector<BYTE>& code, int nextState) {
        // Adicionar código para atualizar state
    }
    
    void AddControlFlowBreak(std::vector<BYTE>& code) {
        // Adicionar break ou continue
    }
    
    void AddWhileLoop(std::vector<BYTE>& code) { /* while (true) */ }
    void AddSwitchStatement(std::vector<BYTE>& code) { /* switch (state) */ }
    void AddCase(std::vector<BYTE>& code, size_t index, const BASIC_BLOCK& block) { /* case X: */ }
    void AddSwitchEnd(std::vector<BYTE>& code) { /* } */ }
    void AddWhileEnd(std::vector<BYTE>& code) { /* } */ }
    
    bool ShouldAddOpaquePredicate(const BASIC_BLOCK& block) {
        return rand() % 3 == 0; // 33% chance
    }
    
    void InsertJunkAtRandomPositions(BASIC_BLOCK& block, const std::vector<INSTRUCTION_INFO>& junk) {
        // Inserir junk em posições aleatórias
    }
    
    void UpdateBlockIndices() {
        // Atualizar índices após reordering
    }
    
    void UpdateFlowEdges() {
        // Atualizar arestas após reordering
    }
    
    uint32_t GenerateRandomKey() {
        return rand();
    }
};
```

### Advanced Control Flow Techniques

```cpp
// Técnicas avançadas de ofuscação de fluxo de controle
class AdvancedControlFlowObfuscator : public ControlFlowObfuscator {
private:
    std::vector<ADVANCED_TECHNIQUE> advancedTechniques;
    
public:
    AdvancedControlFlowObfuscator() {
        InitializeAdvancedTechniques();
    }
    
    void InitializeAdvancedTechniques() {
        advancedTechniques.push_back({TECHNIQUE_DUPLICATE_BLOCKS, "Duplicate blocks with opaque predicates"});
        advancedTechniques.push_back({TECHNIQUE_IRREDUCIBLE_FLOW, "Create irreducible control flow"});
        advancedTechniques.push_back({TECHNIQUE_EXCEPTION_DISPATCHING, "Exception-based dispatching"});
        advancedTechniques.push_back({TECHNIQUE_POINTER_CONFUSION, "Function pointer confusion"});
    }
    
    void ApplyAdvancedObfuscation() {
        // Aplicar técnicas básicas primeiro
        ControlFlowObfuscator::ObfuscateControlFlow(cfg.functionAddress, cfg.functionSize);
        
        // Aplicar técnicas avançadas
        for (const ADVANCED_TECHNIQUE& tech : advancedTechniques) {
            ApplyAdvancedTechnique(tech);
        }
    }
    
    void ApplyAdvancedTechnique(const ADVANCED_TECHNIQUE& tech) {
        switch (tech.type) {
            case TECHNIQUE_DUPLICATE_BLOCKS:
                ApplyDuplicateBlocks();
                break;
            case TECHNIQUE_IRREDUCIBLE_FLOW:
                ApplyIrreducibleFlow();
                break;
            case TECHNIQUE_EXCEPTION_DISPATCHING:
                ApplyExceptionDispatching();
                break;
            case TECHNIQUE_POINTER_CONFUSION:
                ApplyPointerConfusion();
                break;
        }
    }
    
    void ApplyDuplicateBlocks() {
        // Duplicar blocos com predicados opacos
        std::vector<BASIC_BLOCK> newBlocks;
        
        for (const BASIC_BLOCK& block : cfg.basicBlocks) {
            // Adicionar bloco original
            newBlocks.push_back(block);
            
            // Adicionar duplicata com predicado opaco
            BASIC_BLOCK duplicate = block;
            duplicate.isDuplicate = true;
            duplicate.opaquePredicate = GenerateOpaquePredicate();
            
            newBlocks.push_back(duplicate);
        }
        
        cfg.basicBlocks = newBlocks;
    }
    
    void ApplyIrreducibleFlow() {
        // Criar fluxo irredutível
        // Adicionar jumps que criam loops complexos
        
        // Adicionar bloco de dispatcher adicional
        BASIC_BLOCK dispatcherBlock;
        dispatcherBlock.isDispatcher = true;
        GenerateIrreducibleDispatcher(dispatcherBlock);
        
        cfg.basicBlocks.push_back(dispatcherBlock);
        
        // Modificar arestas para criar fluxo complexo
        CreateIrreducibleEdges();
    }
    
    void GenerateIrreducibleDispatcher(BASIC_BLOCK& block) {
        // Gerar dispatcher que salta para blocos aleatoriamente
        block.dispatcherCode = GenerateRandomDispatcher();
    }
    
    std::vector<BYTE> GenerateRandomDispatcher() {
        std::vector<BYTE> code;
        
        // Código que escolhe bloco aleatoriamente
        // srand(time(NULL));
        // int targetBlock = rand() % cfg.basicBlocks.size();
        // goto block_targetBlock;
        
        return code;
    }
    
    void CreateIrreducibleEdges() {
        // Criar arestas que tornam o grafo irredutível
        // Adicionar jumps de qualquer bloco para qualquer outro
        for (size_t i = 0; i < cfg.basicBlocks.size(); i++) {
            for (size_t j = 0; j < cfg.basicBlocks.size(); j++) {
                if (i != j && rand() % 10 == 0) { // 10% chance
                    AddEdge(i, j);
                }
            }
        }
    }
    
    void ApplyExceptionDispatching() {
        // Usar exceptions para controle de fluxo
        InstallExceptionHandler();
        
        // Modificar blocos para lançar exceptions
        for (BASIC_BLOCK& block : cfg.basicBlocks) {
            AddExceptionDispatching(block);
        }
    }
    
    void InstallExceptionHandler() {
        // Instalar VEH para lidar com exceptions
        cfg.exceptionHandler = AddVectoredExceptionHandler(1, ExceptionDispatcher);
    }
    
    void AddExceptionDispatching(BASIC_BLOCK& block) {
        // Adicionar código que lança exception com ID do próximo bloco
        block.exceptionDispatching = true;
        block.exceptionCode = GenerateExceptionCode(block);
    }
    
    std::vector<BYTE> GenerateExceptionCode(const BASIC_BLOCK& block) {
        std::vector<BYTE> code;
        
        // RaiseException com código específico
        // RaiseException(block.index, 0, 0, NULL);
        
        return code;
    }
    
    void ApplyPointerConfusion() {
        // Usar ponteiros de função para confundir fluxo
        GenerateFunctionPointers();
        
        // Modificar chamadas para usar ponteiros
        for (BASIC_BLOCK& block : cfg.basicBlocks) {
            ReplaceCallsWithPointers(block);
        }
    }
    
    void GenerateFunctionPointers() {
        // Criar array de ponteiros de função
        cfg.functionPointers.clear();
        
        for (const BASIC_BLOCK& block : cfg.basicBlocks) {
            cfg.functionPointers.push_back((PVOID)block.startAddress);
        }
        
        // Embaralhar array
        std::random_shuffle(cfg.functionPointers.begin(), cfg.functionPointers.end());
    }
    
    void ReplaceCallsWithPointers(BASIC_BLOCK& block) {
        // Substituir chamadas diretas por indiretas via ponteiros
        for (INSTRUCTION_INFO& inst : block.instructions) {
            if (IsCall(inst)) {
                ConvertToIndirectCall(inst);
            }
        }
    }
    
    void ConvertToIndirectCall(INSTRUCTION_INFO& inst) {
        // CALL direct -> CALL [functionPointers + offset]
        inst.isIndirectCall = true;
        inst.pointerIndex = rand() % cfg.functionPointers.size();
    }
    
    // Exception dispatcher
    static LONG CALLBACK ExceptionDispatcher(PEXCEPTION_POINTERS ExceptionInfo) {
        DWORD exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
        
        // Verificar se é nosso código de exception
        if (exceptionCode >= EXCEPTION_BLOCK_START && exceptionCode <= EXCEPTION_BLOCK_END) {
            // Extrair índice do bloco
            size_t blockIndex = exceptionCode - EXCEPTION_BLOCK_START;
            
            // Modificar RIP para pular para o bloco correto
            ExceptionInfo->ContextRecord->Rip = (DWORD64)cfg.basicBlocks[blockIndex].startAddress;
            
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    // Constantes
    static const DWORD EXCEPTION_BLOCK_START = 0xE0000000;
    static const DWORD EXCEPTION_BLOCK_END = 0xE000FFFF;
};
```

### Por que é Detectado

> [!WARNING]
> **Control flow obfuscation deixa rastros através de padrões estruturais e anomalias comportamentais**

#### 1. Structural Analysis
```cpp
// Análise estrutural
class StructuralAnalyzer {
private:
    std::vector<STRUCTURAL_ANOMALY> knownAnomalies;
    
public:
    void AnalyzeControlFlow(PVOID functionAddress, SIZE_T functionSize) {
        // Construir CFG
        CONTROL_FLOW_GRAPH cfg = BuildCFG(functionAddress, functionSize);
        
        // Analisar estrutura
        AnalyzeCFGStructure(cfg);
        
        // Detectar anomalias
        DetectStructuralAnomalies(cfg);
    }
    
    CONTROL_FLOW_GRAPH BuildCFG(PVOID functionAddress, SIZE_T functionSize) {
        CONTROL_FLOW_GRAPH cfg;
        // Implementar construção de CFG
        return cfg;
    }
    
    void AnalyzeCFGStructure(const CONTROL_FLOW_GRAPH& cfg) {
        // Calcular métricas estruturais
        double cyclomaticComplexity = CalculateCyclomaticComplexity(cfg);
        double averageBlockSize = CalculateAverageBlockSize(cfg);
        double branchingFactor = CalculateBranchingFactor(cfg);
        
        // Verificar anomalias
        if (cyclomaticComplexity > 50) {
            ReportHighComplexity();
        }
        
        if (averageBlockSize < 3) {
            ReportSmallBlocks();
        }
        
        if (branchingFactor > 10) {
            ReportHighBranching();
        }
    }
    
    void DetectStructuralAnomalies(const CONTROL_FLOW_GRAPH& cfg) {
        // Detectar flattening
        if (DetectControlFlowFlattening(cfg)) {
            ReportFlatteningDetected();
        }
        
        // Detectar junk code
        if (DetectJunkCode(cfg)) {
            ReportJunkCodeDetected();
        }
        
        // Detectar opaque predicates
        if (DetectOpaquePredicates(cfg)) {
            ReportOpaquePredicatesDetected();
        }
    }
    
    bool DetectControlFlowFlattening(const CONTROL_FLOW_GRAPH& cfg) {
        // Procurar por padrão de switch + state variable
        return HasSwitchStatement(cfg) && HasStateVariable(cfg);
    }
    
    bool DetectJunkCode(const CONTROL_FLOW_GRAPH& cfg) {
        // Procurar por blocos com alta densidade de NOPs
        for (const BASIC_BLOCK& block : cfg.basicBlocks) {
            if (CalculateJunkRatio(block) > 0.3) { // 30% junk
                return true;
            }
        }
        return false;
    }
    
    bool DetectOpaquePredicates(const CONTROL_FLOW_GRAPH& cfg) {
        // Procurar por condições sempre verdadeiras/falsas
        for (const BASIC_BLOCK& block : cfg.basicBlocks) {
            for (const OPAQUE_PREDICATE& pred : block.opaquePredicates) {
                if (IsObviouslyOpaque(pred)) {
                    return true;
                }
            }
        }
        return false;
    }
    
    double CalculateCyclomaticComplexity(const CONTROL_FLOW_GRAPH& cfg) {
        // E = arestas, N = nós, P = componentes conectados
        size_t E = cfg.edges.size();
        size_t N = cfg.basicBlocks.size();
        size_t P = 1; // Assume connected
        
        return E - N + 2 * P;
    }
    
    double CalculateAverageBlockSize(const CONTROL_FLOW_GRAPH& cfg) {
        if (cfg.basicBlocks.empty()) return 0;
        
        size_t totalSize = 0;
        for (const BASIC_BLOCK& block : cfg.basicBlocks) {
            totalSize += block.instructions.size();
        }
        
        return (double)totalSize / cfg.basicBlocks.size();
    }
    
    double CalculateBranchingFactor(const CONTROL_FLOW_GRAPH& cfg) {
        if (cfg.basicBlocks.empty()) return 0;
        
        size_t totalBranches = 0;
        for (const BASIC_BLOCK& block : cfg.basicBlocks) {
            // Contar sucessores
            totalBranches += CountSuccessors(block);
        }
        
        return (double)totalBranches / cfg.basicBlocks.size();
    }
    
    size_t CountSuccessors(const BASIC_BLOCK& block) {
        size_t count = 0;
        // Contar arestas saindo do bloco
        return count;
    }
    
    double CalculateJunkRatio(const BASIC_BLOCK& block) {
        size_t junkInstructions = 0;
        for (const INSTRUCTION_INFO& inst : block.instructions) {
            if (IsJunkInstruction(inst)) {
                junkInstructions++;
            }
        }
        
        return (double)junkInstructions / block.instructions.size();
    }
    
    bool IsJunkInstruction(const INSTRUCTION_INFO& inst) {
        return strcmp(inst.mnemonic, "NOP") == 0 ||
               strcmp(inst.mnemonic, "XCHG") == 0; // XCHG EAX, EAX
    }
    
    bool HasSwitchStatement(const CONTROL_FLOW_GRAPH& cfg) {
        // Verificar se há switch statement no código
        return false; // Placeholder
    }
    
    bool HasStateVariable(const CONTROL_FLOW_GRAPH& cfg) {
        // Verificar se há variável de estado
        return false; // Placeholder
    }
    
    bool IsObviouslyOpaque(const OPAQUE_PREDICATE& pred) {
        // Verificar se predicado é obviamente sempre true/false
        return pred.condition.find("x * x - x * x") != std::string::npos;
    }
    
    void ReportHighComplexity() {
        std::cout << "High cyclomatic complexity detected" << std::endl;
    }
    
    void ReportSmallBlocks() {
        std::cout << "Unusually small basic blocks detected" << std::endl;
    }
    
    void ReportHighBranching() {
        std::cout << "High branching factor detected" << std::endl;
    }
    
    void ReportFlatteningDetected() {
        std::cout << "Control flow flattening detected" << std::endl;
    }
    
    void ReportJunkCodeDetected() {
        std::cout << "Junk code detected" << std::endl;
    }
    
    void ReportOpaquePredicatesDetected() {
        std::cout << "Opaque predicates detected" << std::endl;
    }
};
```

#### 2. Dynamic Analysis
```cpp
// Análise dinâmica
class DynamicAnalyzer {
private:
    std::map<PVOID, EXECUTION_PROFILE> executionProfiles;
    
public:
    void MonitorExecution(PVOID functionAddress) {
        // Instalar hooks para monitorar execução
        InstallExecutionHooks();
        
        // Executar função e monitorar
        ExecuteAndMonitor(functionAddress);
        
        // Analisar perfil de execução
        AnalyzeExecutionProfile();
    }
    
    void InstallExecutionHooks() {
        // Hook instruções críticas
    }
    
    void ExecuteAndMonitor(PVOID functionAddress) {
        // Executar função em ambiente controlado
        typedef void (*FunctionPtr)();
        FunctionPtr func = (FunctionPtr)functionAddress;
        
        // Monitorar execução
        StartExecutionMonitoring();
        
        try {
            func();
        } catch (...) {
            // Capturar exceptions
        }
        
        StopExecutionMonitoring();
    }
    
    void StartExecutionMonitoring() {
        // Iniciar monitoramento
    }
    
    void StopExecutionMonitoring() {
        // Parar monitoramento
    }
    
    void AnalyzeExecutionProfile() {
        for (const auto& pair : executionProfiles) {
            const EXECUTION_PROFILE& profile = pair.second;
            
            // Verificar anomalias
            if (HasUnusualExecutionPattern(profile)) {
                ReportUnusualExecution(profile);
            }
        }
    }
    
    bool HasUnusualExecutionPattern(const EXECUTION_PROFILE& profile) {
        // Verificar padrões de execução suspeitos
        return profile.exceptionFrequency > 10 || // Muitas exceptions
               profile.junkExecutionRatio > 0.5 || // Muito junk code executado
               profile.loopCount > 1000; // Loops excessivos
    }
    
    void ReportUnusualExecution(const EXECUTION_PROFILE& profile) {
        std::cout << "Unusual execution pattern detected" << std::endl;
    }
};
```

#### 3. Code Pattern Recognition
```cpp
// Reconhecimento de padrões de código
class PatternRecognizer {
private:
    std::vector<CODE_PATTERN> knownPatterns;
    
public:
    void InitializePatterns() {
        // Padrões de ofuscação conhecidos
        knownPatterns.push_back({PATTERN_STATE_MACHINE, "State machine pattern"});
        knownPatterns.push_back({PATTERN_OPAQUE_CALCULATION, "Opaque calculation pattern"});
        knownPatterns.push_back({PATTERN_JUNK_SEQUENCE, "Junk instruction sequence"});
    }
    
    void ScanForPatterns(PVOID codeAddress, SIZE_T codeSize) {
        BYTE* code = (BYTE*)codeAddress;
        
        for (const CODE_PATTERN& pattern : knownPatterns) {
            if (FindPattern(code, codeSize, pattern)) {
                ReportPatternFound(pattern);
            }
        }
    }
    
    bool FindPattern(BYTE* code, SIZE_T size, const CODE_PATTERN& pattern) {
        // Implementar busca de padrões
        return false; // Placeholder
    }
    
    void ReportPatternFound(const CODE_PATTERN& pattern) {
        std::cout << "Obfuscation pattern detected: " << pattern.description << std::endl;
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Structural analysis | < 30s | 85% |
| VAC Live | Dynamic execution monitoring | Imediato | 80% |
| BattlEye | Pattern recognition | < 1 min | 90% |
| Faceit AC | Behavioral analysis | < 30s | 75% |

---

## 🔄 Alternativas Seguras

### 1. Mixed Boolean-Arithmetic Obfuscation
```cpp
// ✅ Ofuscação mista booleana-aritmética
class MixedBooleanArithmeticObfuscator {
public:
    std::string ObfuscateExpression(const std::string& expression) {
        // Transformar expressão usando MBA (Mixed Boolean-Arithmetic)
        
        // Exemplo: x + y -> (x ^ y) + 2*(x & y)
        // Ou: x == y -> (x ^ y) == 0
        
        return ApplyMBAObfuscation(expression);
    }
    
    std::string ApplyMBAObfuscation(const std::string& expr) {
        // Implementar transformações MBA
        std::string obfuscated = expr;
        
        // Substituir operações aritméticas
        obfuscated = ReplaceAddition(obfuscated);
        obfuscated = ReplaceSubtraction(obfuscated);
        obfuscated = ReplaceEquality(obfuscated);
        
        return obfuscated;
    }
    
    std::string ReplaceAddition(std::string expr) {
        // x + y -> (x ^ y) + 2*(x & y)
        size_t pos = expr.find('+');
        if (pos != std::string::npos) {
            std::string left = expr.substr(0, pos);
            std::string right = expr.substr(pos + 1);
            
            return "(" + left + " ^ " + right + ") + 2*(" + left + " & " + right + ")";
        }
        return expr;
    }
    
    std::string ReplaceSubtraction(std::string expr) {
        // x - y -> (x ^ y) - 2*(x & y)
        size_t pos = expr.find('-');
        if (pos != std::string::npos) {
            std::string left = expr.substr(0, pos);
            std::string right = expr.substr(pos + 1);
            
            return "(" + left + " ^ " + right + ") - 2*(" + left + " & " + right + ")";
        }
        return expr;
    }
    
    std::string ReplaceEquality(std::string expr) {
        // x == y -> ((x ^ y) == 0)
        size_t pos = expr.find("==");
        if (pos != std::string::npos) {
            std::string left = expr.substr(0, pos);
            std::string right = expr.substr(pos + 2);
            
            return "(" + left + " ^ " + right + ") == 0";
        }
        return expr;
    }
};
```

### 2. Virtualization-Based Obfuscation
```cpp
// ✅ Ofuscação baseada em virtualização
class VirtualizationObfuscator {
private:
    VIRTUAL_MACHINE vm;
    
public:
    void VirtualizeFunction(PVOID functionAddress, SIZE_T functionSize) {
        // Converter função em bytecode de VM
        std::vector<BYTE> bytecode = ConvertToBytecode(functionAddress, functionSize);
        
        // Criar interpretador de VM
        std::vector<BYTE> interpreter = GenerateInterpreter();
        
        // Combinar
        std::vector<BYTE> virtualizedCode;
        virtualizedCode.insert(virtualizedCode.end(), interpreter.begin(), interpreter.end());
        virtualizedCode.insert(virtualizedCode.end(), bytecode.begin(), bytecode.end());
        
        // Substituir função original
        ReplaceFunction(functionAddress, functionSize, virtualizedCode);
    }
    
    std::vector<BYTE> ConvertToBytecode(PVOID functionAddress, SIZE_T functionSize) {
        // Converter código nativo para bytecode customizado
        std::vector<BYTE> bytecode;
        
        // Implementar conversão
        return bytecode;
    }
    
    std::vector<BYTE> GenerateInterpreter() {
        // Gerar interpretador que executa o bytecode
        std::vector<BYTE> interpreter;
        
        // Interpreter loop
        // while (true) {
        //     BYTE opcode = *ip++;
        //     switch (opcode) {
        //         case ADD: // etc.
        //     }
        // }
        
        return interpreter;
    }
    
    void ReplaceFunction(PVOID address, SIZE_T size, const std::vector<BYTE>& newCode) {
        // Substituir função com código virtualizado
        DWORD oldProtect;
        VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(address, newCode.data(), min(size, newCode.size()));
        VirtualProtect(address, size, oldProtect, &oldProtect);
    }
};
```

### 3. Code Mobility Techniques
```cpp
// ✅ Técnicas de mobilidade de código
class CodeMobilityObfuscator {
public:
    void ApplyCodeMobility(PVOID functionAddress, SIZE_T functionSize) {
        // Dividir função em fragmentos móveis
        std::vector<CODE_FRAGMENT> fragments = FragmentFunction(functionAddress, functionSize);
        
        // Distribuir fragmentos na memória
        DistributeFragments(fragments);
        
        // Criar dispatcher móvel
        CreateMobileDispatcher(fragments);
    }
    
    std::vector<CODE_FRAGMENT> FragmentFunction(PVOID address, SIZE_T size) {
        std::vector<CODE_FRAGMENT> fragments;
        
        BYTE* code = (BYTE*)address;
        SIZE_T offset = 0;
        
        while (offset < size) {
            CODE_FRAGMENT fragment;
            fragment.originalOffset = offset;
            fragment.size = GenerateRandomFragmentSize();
            
            if (offset + fragment.size > size) {
                fragment.size = size - offset;
            }
            
            fragment.code.assign(code + offset, code + offset + fragment.size);
            fragments.push_back(fragment);
            
            offset += fragment.size;
        }
        
        return fragments;
    }
    
    void DistributeFragments(const std::vector<CODE_FRAGMENT>& fragments) {
        // Alocar fragmentos em locais aleatórios da memória
        for (CODE_FRAGMENT& fragment : fragments) {
            fragment.newAddress = AllocateRandomMemory(fragment.size);
            memcpy(fragment.newAddress, fragment.code.data(), fragment.size);
        }
    }
    
    void CreateMobileDispatcher(const std::vector<CODE_FRAGMENT>& fragments) {
        // Criar dispatcher que salta entre fragmentos
        std::vector<BYTE> dispatcher;
        
        for (size_t i = 0; i < fragments.size(); i++) {
            // Código para executar fragmento i
            AddFragmentExecution(dispatcher, fragments[i]);
            
            // Código para saltar para próximo fragmento
            if (i + 1 < fragments.size()) {
                AddJumpToNext(dispatcher, fragments[i + 1]);
            }
        }
        
        // Substituir função original
        ReplaceWithDispatcher(fragments[0].originalAddress, dispatcher);
    }
    
    void AddFragmentExecution(std::vector<BYTE>& dispatcher, const CODE_FRAGMENT& fragment) {
        // CALL fragment.newAddress ou JMP
    }
    
    void AddJumpToNext(std::vector<BYTE>& dispatcher, const CODE_FRAGMENT& nextFragment) {
        // JMP nextFragment.newAddress
    }
    
    void ReplaceWithDispatcher(PVOID originalAddress, const std::vector<BYTE>& dispatcher) {
        // Substituir função original com dispatcher
    }
    
    SIZE_T GenerateRandomFragmentSize() {
        // Tamanho aleatório entre 16-64 bytes
        return 16 + (rand() % 49);
    }
    
    PVOID AllocateRandomMemory(SIZE_T size) {
        // Alocar em endereço aleatório
        return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
};
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | Static analysis |
| 2020-2024 | ⚠️ Médio risco | Dynamic analysis |
| 2025-2026 | ⚠️ Alto risco | Advanced pattern recognition |

---

## 🎯 Lições Aprendidas

1. **Estrutura é Rastreada**: CFG anormal revela ofuscação.

2. **Complexidade é Analisada**: Alta complexidade ciclomática é suspeita.

3. **Padrões São Reconhecidos**: Técnicas comuns são detectadas por assinatura.

4. **MBA é Mais Seguro**: Mixed Boolean-Arithmetic é mais stealth.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#43]]
- [[Mixed_Boolean_Arithmetic]]
- [[Code_Virtualization]]
- [[Control_Flow_Flattening]]

---

*Control flow obfuscation tem risco moderado. Considere MBA obfuscation para mais stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
