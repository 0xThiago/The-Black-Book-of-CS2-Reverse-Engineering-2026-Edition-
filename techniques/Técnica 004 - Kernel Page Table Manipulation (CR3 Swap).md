# Técnica 004 - Kernel Page Table Manipulation (CR3 Swap)

📅 Criado em: 2026-02-15
🔗 Tags: #kernel #memory #cr3 #stealth

## 📌 Resumo
> **Status:** ✅ Atual / Melhor Prática (2026)
> **Risco de Detecção:** 🟢 Mínimo
> **Ponte C++:** Substitui o uso de `ReadProcessMemory` por manipulação direta de estruturas de dados do processador (MMU).

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[DATABASE]]
- [[Técnica 054 - Rust Kernel RW]]

---

## 🔍 Desenvolvimento Técnico

A manipulação de tabelas de página (Page Tables) permite que um driver de kernel acesse a memória de qualquer processo sem utilizar APIs do Windows que disparam callbacks de segurança.

### 🧠 Como Funciona (Ring 0)

1.  **Diretório de Páginas (CR3):** Cada processo tem seu próprio diretório de tabelas de página, cujo endereço físico é armazenado no registrador `CR3` da CPU durante o contexto do processo.
2.  **Tradução Manual:** O cheat lê o `CR3` do processo alvo e realiza a tradução de endereço virtual para físico manualmente, seguindo a estrutura de 4 ou 5 níveis (PML4/PML5).
3.  **Acesso Direto:** Uma vez que o endereço físico é obtido, o cheat usa `MmMapIoSpace` ou mapeia a página física diretamente no seu próprio espaço de endereçamento.

---

## 🛡️ Por que é Seguro?

- **Bypass de ObRegisterCallbacks:** Não há abertura de handles.
- **Invisível para Scanners de VAD:** Como não alteramos as permissões das páginas via `VirtualProtect`, os descritores de endereço virtual (VAD) permanecem limpos.
- **Hardware-level:** A operação acontece em um nível abaixo do que a maioria dos anti-cheats usermode consegue monitorar.

---
📌 **Ponte C++:** Em C++, esta técnica geralmente envolve código assembly inline ou intrínsecos como `__readcr3()`. No Rust, utilizamos wrappers seguros em torno dessas operações para garantir que a manipulação da memória física não cause um BSoD por acesso a páginas descarregadas (paged out).
