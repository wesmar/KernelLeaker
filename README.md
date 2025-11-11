# KernelLeaker

## Defeating KASLR Through Cache Timing Side-Channels: A Deep Dive Into Microarchitectural Exploitation

### Abstract

Kernel Address Space Layout Randomization (KASLR) represents one of the fundamental security mechanisms in modern operating systems, designed to prevent exploitation by randomizing the location of kernel code in virtual memory. This work presents a comprehensive analysis of cache timing side-channel attacks capable of defeating KASLR on x64 Windows systems through prefetch instruction timing analysis. The research demonstrates that microarchitectural behavior differences between mapped and unmapped memory pages create measurable timing signatures that can be exploited to leak the kernel base address with high reliability.

The implementation achieves 100% success rate on Intel i7-9750H (Dell XPS-7590) through architecture-specific timing analysis and statistical noise filtering techniques. While empirical validation was limited to this specific hardware configuration, the methodology presents a generalized framework applicable across different CPU vendors and microarchitectural variants.

---

## Table of Contents

- [Introduction](#1-introduction-the-kaslr-problem)
- [Microarchitectural Foundations](#2-microarchitectural-foundations)
- [Timing Measurement Methodology](#3-timing-measurement-methodology)
- [Vendor-Specific Signatures](#4-vendor-specific-microarchitectural-signatures)
- [Statistical Reliability](#5-statistical-reliability-through-voting)
- [Address Space Scanning](#6-address-space-scanning-strategy)
- [Environmental Optimization](#7-environmental-optimization)
- [Practical Results](#8-practical-deployment-and-results)
- [AMD Implementation](#9-the-amd-uncertainty)
- [Implications](#10-implications-and-mitigations)
- [Future Research](#11-future-research-directions)
- [Building](#building-and-usage)
- [Disclaimer](#disclaimer)

---

## 1. Introduction: The KASLR Problem

### 1.1 The Security Landscape

Modern operating systems employ multiple layers of defense against memory corruption exploits. Among these, Address Space Layout Randomization (ASLR) stands as a critical mitigation technique, randomizing the location of executable code, libraries, and data structures in virtual memory. The kernel-space variant, KASLR, extends this protection to the operating system kernel itself.

On 64-bit Windows systems, the kernel typically resides within the canonical address space range `0xFFFFF80000000000` to `0xFFFFF80800000000`. KASLR randomizes the exact base address within this range during boot, creating uncertainty for potential attackers. Without knowledge of the kernel base address, exploitation of kernel vulnerabilities becomes significantly more difficult, as attackers cannot reliably locate kernel functions or data structures.

However, KASLR's security relies on a fundamental assumption: that the randomized address cannot be leaked through side channels. This research demonstrates that this assumption does not hold when considering microarchitectural timing side-channels.

### 1.2 The Cache Timing Attack Vector

Modern CPUs employ complex cache hierarchies and speculative execution mechanisms to achieve high performance. These optimizations create timing differences that can be measured and exploited. When a CPU attempts to access memory, the operation's latency depends on numerous factors:

- Whether the address is mapped in the page tables
- Whether the data resides in L1, L2, or L3 cache
- Whether the CPU's prefetcher can predict the access pattern
- Whether speculative execution has already loaded the data

The critical insight is this: the CPU's Memory Management Unit (MMU) behaves differently when translating virtual addresses that are mapped versus unmapped. Even though userspace code cannot directly access kernel memory, the mere attempt to prefetch kernel addresses creates measurable timing signatures.

**Think of it like this:** imagine a library with restricted sections. You cannot enter the restricted section, but you can ask the librarian if a book exists there. If the librarian takes 5 seconds to respond "access denied" for real books versus 1 second for non-existent books, you have learned something about the library's inventory without ever accessing the restricted section. The CPU's timing behavior is our "librarian response time."

### 1.3 Research Scope and Limitations

This research was conducted exclusively on an Intel i7-9750H processor (Coffee Lake microarchitecture) in a Dell XPS-7590 laptop running Windows 11 25H2 Build 26200.7019. The achieved success rate of 100% across multiple test iterations demonstrates the technique's reliability on this specific configuration.

However, several important limitations must be acknowledged:

**Hardware Diversity:** Modern CPU architectures vary significantly in their cache hierarchies, prefetch mechanisms, and MMU implementations. Intel, AMD, and ARM processors each exhibit distinct timing characteristics. The AMD-specific implementation presented here represents educated hypotheses based on documented architectural differences, but lacks empirical hardware validation.

**Microarchitectural Evolution:** Newer CPU generations (Intel 12th gen and beyond, AMD Zen 4+) may implement different prefetch behaviors or timing characteristics. They may prove more vulnerable, equally vulnerable, or more resistant to these techniques. Without access to diverse hardware configurations, definitive statements cannot be made.

**Mitigation Awareness:** CPU vendors continuously evolve their microarchitectural designs. Some timing channels may be inadvertently closed or widened in future silicon revisions. The technique's longevity across CPU generations remains an open question.

Despite these constraints, the methodology demonstrates fundamental principles of cache timing analysis that transcend specific hardware implementations. The statistical techniques, noise filtering algorithms, and vendor-specific adaptation strategies provide a framework applicable to future research.

---

## 2. Microarchitectural Foundations

### 2.1 CPU Cache Hierarchy: A Primer

To understand cache timing attacks, we must first understand what caches actually are and why they exist. Modern CPUs operate at frequencies measured in gigahertz (billions of cycles per second), while main memory (RAM) operates at much slower speeds. This speed disparity creates a fundamental performance bottleneck.

Consider these approximate access latencies on a typical modern Intel CPU:

- **L1 Cache:** ~4 cycles (~1 nanosecond at 3GHz)
- **L2 Cache:** ~12 cycles (~4 nanoseconds)
- **L3 Cache:** ~40-75 cycles (~15-25 nanoseconds)
- **Main Memory (RAM):** ~200-300 cycles (~100 nanoseconds)

The performance difference is not linear - it is multiplicative. An L1 cache hit is roughly 50-75 times faster than a main memory access. This is why modern CPUs dedicate significant die space to cache memory.

A real-world analogy helps here: imagine you are a chef in a kitchen. Your L1 cache is the counter directly in front of you - ingredients here are instantly accessible. Your L2 cache is the refrigerator - a few steps away, requiring a moment to open and retrieve items. Your L3 cache is the pantry down the hall - requires walking but still relatively quick. Main memory is the grocery store - requires leaving the building entirely.

If you are cooking and need salt, you would much prefer it to be on your counter (L1) rather than requiring a trip to the store (RAM). The CPU faces the same preference.

### 2.2 Cache Lines and Spatial Locality

Caches do not store individual bytes - they store **cache lines**, typically 64 bytes in modern x64 architectures. When you access a single byte at address `0x1000`, the CPU loads the entire cache line containing addresses `0x1000-0x103F` (assuming 64-byte alignment).

This design exploits **spatial locality**: if you access one memory location, you are likely to access nearby locations soon. Arrays, structures, and sequential code all exhibit spatial locality.

The mathematical implication is important: each cache line covers 2^6 = 64 bytes. A 32KB L1 cache therefore contains 32768 / 64 = 512 cache lines. Each cache line can store data from any memory address, but the caching mechanism must maintain metadata tracking which address each cache line currently holds.

### 2.3 The Prefetch Mechanism

Modern CPUs do not wait passively for memory requests - they anticipate them. Hardware prefetchers monitor memory access patterns and speculatively load data into cache before it is explicitly requested.

The x64 instruction set includes explicit prefetch instructions that allow software to provide hints to the CPU:
```asm
prefetchnta byte ptr [address]  ; Non-temporal, bypasses cache
prefetcht0 byte ptr [address]   ; Prefetch to all cache levels
prefetcht1 byte ptr [address]   ; Prefetch to L2 and L3
prefetcht2 byte ptr [address]   ; Prefetch to L3 only
```

These instructions **do not cause page faults** if the address is unmapped. According to Intel's architecture manual, prefetch instructions that reference unmapped pages are treated as NOPs (no operation). However - and this is critical - **the CPU must still consult the MMU to determine whether the page is mapped**.

This MMU consultation takes time. And this time is measurable.

### 2.4 The MMU and Page Table Walks

The Memory Management Unit (MMU) translates virtual addresses to physical addresses using page tables. On x64 systems, this involves a four-level page table hierarchy:

1. Page Map Level 4 (PML4)
2. Page Directory Pointer Table (PDPT)
3. Page Directory (PD)
4. Page Table (PT)

For a mapped kernel address, the MMU traverses these tables, finds the physical page, and caches the translation in the Translation Lookaside Buffer (TLB). For an unmapped address, the traversal fails at some level, and no TLB entry is created.

The timing difference arises from several factors:

**TLB Hits vs Misses:** If a translation is already in the TLB, lookup is extremely fast (~1 cycle). A TLB miss requires a full page table walk, consuming 10-20+ cycles depending on where the walk terminates.

**Cache Behavior:** Page table entries themselves may be cached in L1/L2/L3. A page table walk for a frequently-accessed kernel region will hit in cache, while a walk for an unmapped address will miss.

**Speculative Execution:** Modern CPUs speculatively execute beyond prefetch instructions. For mapped addresses, speculation may successfully load data. For unmapped addresses, speculation must be squashed when the unmapped status is determined.

These factors combine to create measurable timing differences between mapped and unmapped addresses.

---

## 3. Timing Measurement Methodology

### 3.1 The Time Stamp Counter (TSC)

The x64 architecture provides the `RDTSC` (Read Time Stamp Counter) instruction, which reads a 64-bit counter that increments with each CPU cycle. On modern systems, the TSC is invariant - it increments at a constant rate regardless of frequency scaling or power management.

However, RDTSC alone is insufficient for precise timing measurements because:

1. It is not serializing - the CPU may execute it out-of-order
2. Speculative execution may distort results
3. Memory operations may be reordered around it

The x64 architecture provides `RDTSCP`, a serializing variant that ensures all prior instructions have completed before reading the TSC. Combined with memory fence instructions, we can construct precise timing measurements.

### 3.2 Serialization and Timing Precision

The assembly implementation in `sidechannel.asm` demonstrates proper serialization:
```asm
sidechannel PROC
    push rbx
    push rsi
    push rdi
    
    mov rsi, rcx                    ; Save target address
    
    ; Establish clean timing baseline
    mfence                          ; Memory fence - drain pending stores
    rdtscp                          ; Read TSC (serializing)
    mov r9, rax                     ; Save low 32 bits
    mov r8, rdx                     ; Save high 32 bits
    xor eax, eax                    ; Clear state
    lfence                          ; Load fence - prevent speculation
    
    ; Execute prefetch operations
    prefetchnta byte ptr [rsi]      ; Non-temporal prefetch
    prefetcht2 byte ptr [rsi]       ; L2/L3 prefetch
    
    ; Capture completion timestamp
    lfence                          ; Ensure prefetches complete
    rdtscp                          ; Read ending TSC
    mov edi, eax                    ; Save low 32 bits
    mov esi, edx                    ; Save high 32 bits
    mfence                          ; Ensure global visibility
    
    ; Calculate elapsed cycles
    mov rbx, r8                     
    shl rbx, 32                     ; Shift high to upper 32 bits
    or rbx, r9                      ; RBX = start timestamp (64-bit)
    
    mov rax, rsi
    shl rax, 32                     
    or rax, rdi                     ; RAX = end timestamp (64-bit)
    
    sub rax, rbx                    ; Elapsed cycles
    
    pop rdi
    pop rsi
    pop rbx
    ret
sidechannel ENDP
```

Let us analyze the mathematical precision here:

The TSC is read as two 32-bit values: `EDX:EAX` (high:low). To reconstruct the full 64-bit timestamp:
```
timestamp = (high << 32) | low
timestamp = high * 2^32 + low
```

For example, if `EDX=0x00000005` and `EAX=0xA0000000`:
```
timestamp = 0x0000000500000000 | 0xA0000000
timestamp = 0x00000005A0000000
timestamp = 5 * 4294967296 + 2684354560
timestamp = 24159191040 cycles
```

At 3GHz CPU frequency, this represents approximately 8.05 seconds of CPU time.

The elapsed time calculation is simple subtraction:
```
elapsed = end_timestamp - start_timestamp
```

However, achieving single-digit cycle precision requires careful serialization. The `MFENCE` instruction ensures all pending stores are globally visible. The `LFENCE` instruction prevents the CPU from speculatively executing past that point. `RDTSCP` provides a serialization point for instruction ordering.

Without these barriers, the CPU might speculatively execute the prefetch before the starting RDTSCP, or the ending RDTSCP might execute before the prefetch completes, completely invalidating the measurement.

### 3.3 Statistical Noise and Measurement Stability

Even with perfect serialization, timing measurements exhibit noise from numerous sources:

- CPU frequency scaling (turbo boost, power management)
- Operating system interrupts
- SMI (System Management Interrupts)
- Thermal throttling
- Cache evictions from other processes
- TLB evictions
- Branch prediction effects

A single measurement is essentially useless. We must collect multiple samples and apply statistical analysis.

The implementation collects 256 measurements per address (`config::ITERATIONS = 0x100`) plus 5 warm-up measurements that are discarded. The warm-up phase is critical - the first few measurements often exhibit anomalous timing due to cold caches and CPU state transitions.

The average timing for an address is then:
```
average_timing = (sum of 256 measurements) / 256
```

This averaging process reduces random noise by a factor of `sqrt(256) = 16`, according to standard error reduction principles in statistics. If individual measurements have standard deviation σ, the average of N measurements has standard deviation `σ/sqrt(N)`.

### 3.4 The Mode vs Mean Problem

Initially, the implementation used arithmetic mean (average) to characterize the baseline timing. This proved problematic because timing distributions for cache side-channel attacks are often **bimodal** - they exhibit two distinct peaks.

Consider a dataset of timing measurements across the kernel address space:
- 500 addresses are unmapped: timings cluster around 60 cycles
- 12 addresses are mapped (kernel base): timings cluster around 30 cycles

The arithmetic mean would be:
```
mean = (500 * 60 + 12 * 30) / 512
mean = (30000 + 360) / 512
mean = 59.3 cycles
```

This mean is pulled toward the unmapped peak simply because unmapped addresses are more numerous. It does not accurately represent the "typical" unmapped timing.

The **mode** (most frequent value) solves this problem. In the above example, 60 cycles appears 500 times, while 30 cycles appears only 12 times. The mode is 60 cycles - precisely the unmapped baseline we need to identify.

The implementation uses a hash map to compute the mode in O(N) time:
```cpp
uint64_t KernelLeaker::calculate_most_frequent(
    const std::array<uint64_t, config::ARRAY_SIZE>& data)
{
    std::unordered_map<uint64_t, size_t> frequency_map;
    
    uint64_t max_count = 0;
    uint64_t most_frequent_value = 0;

    for (const auto& timing : data) {
        size_t current_count = ++frequency_map[timing];
        
        if (current_count > max_count) {
            max_count = current_count;
            most_frequent_value = timing;
        }
    }

    return most_frequent_value;
}
```

This replaced an earlier O(N²) nested loop implementation. The hash map provides O(1) average-case insertion and lookup, reducing the overall complexity from O(N²) to O(N). For N=512 addresses, this represents a **512x speedup** - from ~262,000 operations to ~512 operations.

The algorithmic improvement is not just about performance; it is about practicality. An O(N²) algorithm that takes several seconds to execute is vulnerable to timing drift and system state changes during execution. An O(N) algorithm that completes in microseconds captures a more consistent snapshot of system state.

---

## 4. Vendor-Specific Microarchitectural Signatures

### 4.1 Intel vs AMD: Inverted Timing Signatures

The most surprising discovery during this research was that Intel and AMD processors exhibit **opposite timing characteristics** for the same attack:

- **Intel Processors:** Mapped kernel pages exhibit LOWER timing (faster prefetch)
- **AMD Processors:** Mapped kernel pages exhibit HIGHER timing (slower prefetch)

This inversion is not arbitrary - it reflects fundamental differences in microarchitectural design philosophy.

### 4.2 Intel Microarchitecture: Aggressive Speculation

Intel's design prioritizes speculative execution and prefetch aggressiveness. When a prefetch instruction references a mapped address:

1. The MMU quickly validates the mapping via TLB or cached page tables
2. The CPU speculatively loads the cache line
3. The prefetch completes in ~30-40 cycles (typical)

When the prefetch references an unmapped address:

1. The MMU attempts translation, traversing page tables
2. The traversal fails, no TLB entry is created
3. The CPU must handle the failed translation
4. The prefetch completes in ~60-80 cycles (typical)

The timing differential on Intel i7-9750H is approximately **2:1 ratio** (unmapped:mapped).

The Intel-specific leak implementation exploits this by searching for consecutive addresses with below-average timing:
```cpp
std::optional<uint64_t> KernelLeaker::leak_intel() const {
    auto data = collect_timings();
    
    avg_timing_ = static_cast<uint32_t>(calculate_most_frequent(data));
    
    // Clamp outliers to average
    for (size_t i = 0; i < config::ARRAY_SIZE; ++i) {
        if (i == 0) continue;
        if (data[i] > avg_timing_) {
            data[i] = avg_timing_;
        }
    }
    
    const uint32_t thresh_1 = avg_timing_ / 10;
    const uint32_t thresh_2 = avg_timing_ / 30;
    
    // Search for consecutive low-timing sections
    for (size_t i = 0; i < config::ARRAY_SIZE - config::KERNEL_SECTIONS; ++i) {
        uint32_t section_avg = 0;
        bool section_valid = true;
        
        for (size_t x = 0; x < config::KERNEL_SECTIONS; ++x) {
            if (data[i + x] >= avg_timing_ - thresh_2) {
                section_valid = false;
                break;
            }
            section_avg += static_cast<uint32_t>(data[i + x]);
        }
        
        if (!section_valid) continue;
        
        section_avg /= static_cast<uint32_t>(config::KERNEL_SECTIONS);
        
        if (section_avg < (avg_timing_ - thresh_1)) {
            return index_to_address(i);
        }
    }
    
    return std::nullopt;
}
```

The threshold calculation is interesting from a signal processing perspective. If the mode (baseline unmapped timing) is M, we search for sections where:
```
section_average < M - (M / 10)
section_average < 0.9M
```

And require all individual measurements in the section to satisfy:
```
individual_timing < M - (M / 30)
individual_timing < 0.967M
```

This creates a two-tier filter: loose individual requirements (96.7% of baseline) but strict aggregate requirements (90% of baseline). The design prevents a single outlier from disqualifying an entire section while maintaining high confidence in the final result.

### 4.3 The Intel Simplified Approach

During development, an even simpler Intel approach emerged that proved more reliable:
```cpp
std::optional KernelLeaker::leak_intel_simple() const {
    auto data = collect_timings();
    
    // Find address with ABSOLUTE MINIMUM timing
    uint64_t min_timing = ~0ull;
    uint64_t best_addr = 0;
    
    for (size_t i = 0; i < config::ARRAY_SIZE; ++i) {
        if (data[i] < min_timing) {
            min_timing = data[i];
            best_addr = index_to_address(i);
        }
    }
    
    // Correct for 1MB offset
    uint64_t corrected_addr = best_addr - 0x100000;
    
    return corrected_addr;
}
```

This approach is almost embarrassingly simple: find the address with the absolute minimum timing, then subtract 1MB (`0x100000` bytes).

**Why the 1MB offset correction is necessary:**

The kernel base itself is not always the lowest-timing address. Empirical testing reveals that the memory region at `kernel_base + 1MB` consistently exhibits the absolute minimum timing. This has a clear microarchitectural explanation:

**1. Windows NT Kernel Image Structure:**
- `kernel_base + 0x000000`: PE header and code sections (.text)
- `kernel_base + 0x100000`: Data sections (.data, .rdata, initialized data, page tables)

**2. Prefetcher Behavior:**
- **Code sections** are often "cold" - executed once during initialization and rarely accessed afterward
- **Data sections** contain frequently-accessed kernel structures (scheduler queues, memory management, process lists)
- CPU prefetchers are optimized for data access patterns, not infrequently-executed code

**3. Cache Warming Effect:**
- The first MB of the kernel (PE header + initialization code) may be evicted from cache after boot
- Subsequent data sections remain "hot" in L2/L3 cache due to continuous kernel operations
- Hot cache entries create persistent TLB entries with lower access latency

**4. Memory Access Patterns:**
- Kernel initialization code executes once at boot time
- Kernel data structures are accessed thousands of times per second during normal operation
- This creates a measurable timing differential favoring the data section region

**Analogy:** Think of a reference book. The table of contents (PE header) is consulted rarely, while frequently-referenced chapters (data sections) remain bookmarked and instantly accessible. The CPU cache behaves similarly - it keeps the "popular pages" readily available.

The mathematical elegance of this approach is its robustness. Complex threshold calculations and statistical filters are fragile - they depend on assumptions about the noise distribution. Simply finding the minimum is parameter-free and works even if the overall timing distribution shifts.

On Intel i7-9750H, this simplified approach achieves 100% reliability with the voting mechanism described later.

### 4.4 AMD Microarchitecture: Speculative Penalties

AMD's Zen microarchitecture exhibits the opposite behavior. When a prefetch instruction references a mapped kernel address, the timing is HIGHER (slower) than for unmapped addresses.

This inverted behavior likely stems from AMD's speculative execution security mitigations. After the Spectre and Meltdown vulnerabilities, AMD implemented more conservative speculative bounds checking. When speculation crosses privilege boundaries (userspace prefetching kernel addresses), additional validation occurs even for mapped pages.

For unmapped addresses, the MMU quickly determines "not mapped" and the prefetch becomes a NOP. For mapped addresses, the MMU must perform additional privilege checks, even though the prefetch itself will not violate permissions.

The result: mapped addresses take ~80-100 cycles, unmapped addresses take ~40-50 cycles.

The AMD leak implementation searches for HIGHER timing clusters:
```cpp
std::optional<uint64_t> KernelLeaker::leak_amd() const {
    auto data = collect_timings();
    
    uint64_t noise_peak = calculate_most_frequent(data);
    
    std::vector<uint64_t> signal_timings;
    const uint32_t noise_threshold = static_cast<uint32_t>(noise_peak / 6);
    
    for (size_t i = 0; i < config::ARRAY_SIZE; ++i) {
        if (data[i] > noise_peak + noise_threshold) {
            signal_timings.push_back(data[i]);
        }
    }
    
    if (signal_timings.empty()) {
        return std::nullopt;
    }
    
    uint64_t signal_total = 0;
    for (const auto& timing : signal_timings) {
        signal_total += timing;
    }
    uint32_t signal_avg = static_cast<uint32_t>(signal_total / signal_timings.size());
    
    // Normalize sub-threshold values to noise floor
    for (size_t i = 0; i < config::ARRAY_SIZE; ++i) {
        if (data[i] < noise_peak) {
            data[i] = noise_peak;
        }
    }
    
    // Search for consecutive high-timing sections
    for (size_t i = 0; i < config::ARRAY_SIZE - config::KERNEL_SECTIONS; ++i) {
        uint32_t section_avg = 0;
        bool section_valid = true;
        
        for (size_t x = 0; x < config::KERNEL_SECTIONS; ++x) {
            if (data[i + x] <= noise_peak + noise_threshold / 2) {
                section_valid = false;
                break;
            }
            section_avg += static_cast<uint32_t>(data[i + x]);
        }
        
        if (!section_valid) continue;
        
        section_avg /= static_cast<uint32_t>(config::KERNEL_SECTIONS);
        
        if (section_avg > noise_peak + noise_threshold) {
            return index_to_address(i);
        }
    }
    
    return std::nullopt;
}
```

The bimodal separation logic is crucial here. We first identify the noise peak (unmapped timing mode), then extract all measurements that significantly exceed this peak:
```
signal_condition: timing > noise_peak + (noise_peak / 6)
```

This creates a secondary distribution containing only the mapped-address timings. We then compute the average of this signal distribution, giving us a clean characterization of "typical mapped timing" uncontaminated by the unmapped majority.

The section search then requires:
```
section_average > noise_peak + noise_threshold
```

This is the inverse of the Intel logic, reflecting the inverted timing signature.

### 4.5 CPU State Stabilization

Between timing measurements, CPU microarchitectural state must be stabilized. Branch prediction buffers, prefetch streams, and speculative execution windows carry state from previous measurements that can contaminate subsequent measurements.

The implementation uses a clever trick - an invalid syscall:
```asm
bad_syscall PROC
    mov eax, 99999                  ; Invalid syscall number
    syscall                         ; Kernel transition
    ret
bad_syscall ENDP
```

Syscall number 99999 does not exist in the Windows kernel. The `syscall` instruction transitions to kernel mode, the kernel immediately returns an error code, and execution returns to userspace.

Why does this help? The kernel transition flushes the CPU pipeline, clears speculative state, and forces completion of all pending memory operations. It acts as a heavyweight serialization barrier that resets the CPU to a clean state.

This is called between every timing measurement:
```cpp
int KernelLeaker::average_sidechannel(void* addr) const {
    bad_syscall();  // Stabilize state
    uint64_t total = sidechannel(addr);
    
    for (size_t i = 0; i < config::ITERATIONS; ++i) {
        total += sidechannel(addr);
    }
    
    return static_cast<int>(total / (config::ITERATIONS + 1));
}
```

The performance cost is minimal (~1000 cycles per syscall) compared to the measurement accuracy benefit.

---

## 5. Statistical Reliability Through Voting

### 5.1 The Consensus Mechanism

Even with perfect microarchitectural understanding, side-channel attacks exhibit probabilistic behavior. Thermal conditions, system load, and quantum effects in transistor switching all introduce irreducible randomness.

Early versions of this tool used a simple retry mechanism: attempt the leak, if it fails, retry; if it succeeds twice consecutively with the same result, accept it. This proved unreliable because consecutive successes could represent correlated noise rather than true signal.

The improved approach uses **majority voting**:
```cpp
std::optional<uint64_t> KernelLeaker::leak_with_retry(
    std::optional<uint64_t> (KernelLeaker::*leak_fn)() const) const
{
    constexpr size_t MAX_ATTEMPTS = 7;
    constexpr size_t REQUIRED_CONSENSUS = 4;
    
    std::unordered_map<uint64_t, size_t> vote_count;
    
    for (size_t attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
        auto current_leak = (this->*leak_fn)();
        
        if (!current_leak) continue;
        
        uint64_t addr = *current_leak;
        size_t votes = ++vote_count[addr];
        
        if (votes >= REQUIRED_CONSENSUS) {
            return addr;  // Early exit on consensus
        }
    }
    
    // Find winner if no early consensus
    if (vote_count.empty()) {
        return std::nullopt;
    }
    
    uint64_t winner = 0;
    size_t max_votes = 0;
    
    for (const auto& [addr, votes] : vote_count) {
        if (votes > max_votes) {
            max_votes = votes;
            winner = addr;
        }
    }
    
    return winner;
}
```

The mathematics of this approach is based on the binomial distribution. If the true leak has probability `p` of success per attempt, and noise has probability `q = (1-p)/N_wrong` where `N_wrong` is the number of possible wrong answers, then:
```
P(consensus on correct answer) = C(7,4) * p^4 * (1-p)^3 
                                + C(7,5) * p^5 * (1-p)^2 
                                + C(7,6) * p^6 * (1-p) 
                                + p^7
```

Where `C(n,k)` is the binomial coefficient "n choose k".

For `p = 0.8` (80% per-attempt accuracy):
```
P(consensus) ≈ 0.96 (96% overall reliability)
```

For `p = 0.6` (60% per-attempt accuracy):
```
P(consensus) ≈ 0.71 (71% overall reliability)
```

The voting threshold of 4/7 was chosen empirically, balancing speed (early exit on consensus) against reliability (requiring majority agreement).

### 5.2 Why Seven Attempts?

The choice of seven attempts is mathematically motivated. We need an odd number to prevent ties. We want enough attempts to achieve high confidence but not so many that execution time becomes impractical.

Consider the confidence intervals:

- **Attempts=3, Threshold=2:** Fast but low confidence (~60% with p=0.6)
- **Attempts=5, Threshold=3:** Better but still marginal (~68% with p=0.6)
- **Attempts=7, Threshold=4:** Good balance (~71% with p=0.6, ~96% with p=0.8)
- **Attempts=9, Threshold=5:** Diminishing returns, longer execution

Seven attempts with threshold four represents the sweet spot. On Intel i7-9750H where per-attempt accuracy is very high (p ≈ 0.9), consensus is typically achieved in 4-5 attempts, rarely requiring all seven.

---

## 6. Address Space Scanning Strategy

### 6.1 The Search Space

Windows x64 kernel addresses occupy the canonical high half of the 64-bit address space:

- **Canonical Low:** `0x0000000000000000` - `0x00007FFFFFFFFFFF` (userspace)
- **Canonical High:** `0xFFFF800000000000` - `0xFFFFFFFFFFFFFFFF` (kernel)

KASLR randomizes the kernel within a specific region:
```cpp
namespace config {
    constexpr uint64_t KERNEL_LOWER_BOUND = 0xFFFFF80000000000ull;
    constexpr uint64_t KERNEL_UPPER_BOUND = 0xFFFFF80800000000ull;
    constexpr uint64_t STEP = 0x100000;  // 1MB
}
```

The kernel base is always aligned to 2MB boundaries (`0x200000`) for large page support, but we scan at 1MB granularity (`0x100000`) to ensure we detect the base even with slight alignment variations.

The search space size is:
```
(0xFFFFF80800000000 - 0xFFFFF80000000000) / 0x100000
= 0x0000000800000000 / 0x100000
= 0x8000
= 32,768 addresses
```

Scanning 32,768 addresses with 256 measurements each would require 8,388,608 timing measurements, taking several minutes. This is impractical.

The implementation scans only the most likely range:
```cpp
constexpr size_t ARRAY_SIZE = (SCAN_END - SCAN_START) / STEP;
// ARRAY_SIZE = 512
```

This reduces the scan to 512 addresses, requiring 131,072 timing measurements, completing in ~5-15 seconds depending on CPU speed.

### 6.2 Why 12 Consecutive Sections?

The kernel is not a single contiguous mapping. It consists of multiple sections: `.text` (code), `.data`, `.rdata` (read-only data), `.pdata` (exception tables), etc. These sections are laid out consecutively in memory.

The implementation searches for 12 consecutive 1MB regions with consistent timing signatures:
```cpp
constexpr size_t KERNEL_SECTIONS = 0xC;  // 12 sections
```

Why 12? Empirical analysis of Windows kernel binaries shows the core kernel image (ntoskrnl.exe) typically spans 10-15 MB. Requiring 12 consecutive sections provides high confidence that we have found the actual kernel base rather than some other mapped structure (drivers, kernel data structures, etc.).

The probability of false positives decreases exponentially with the consecutive section requirement. If random noise creates a false signature at one address with probability `p_false`, the probability of 12 consecutive false signatures is:
```
P(false positive) = p_false^12
```

Even with pessimistic `p_false = 0.1`:
```
P(false positive) = 0.1^12 = 10^-12 (one in a trillion)
```

In practice, `p_false` is much lower, making false positives vanishingly unlikely.

---

## 7. Environmental Optimization

### 7.1 Thread Affinity and Priority

Modern operating systems aggressively migrate threads between CPU cores for load balancing. Each migration invalidates the thread's cache and TLB state, introducing massive noise into timing measurements.

The implementation pins the measurement thread to a single CPU core:
```cpp
class EnvironmentOptimizer {
public:
    EnvironmentOptimizer() {
        DWORD_PTR mask = 1;  // Pin to CPU 0
        SetThreadAffinityMask(GetCurrentThread(), mask);
        
        SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        
        // Warm-up phase
        volatile char dummy[64];
        for (int i = 0; i < 100; ++i) {
            sidechannel(const_cast<char*>(dummy));
        }
    }
};
```

The affinity mask is a bitmask where each bit represents a CPU core:
- `mask = 0x01` (binary: 00000001) pins to core 0
- `mask = 0x02` (binary: 00000010) pins to core 1
- `mask = 0x04` (binary: 00000100) pins to core 2

Setting the thread priority to `THREAD_PRIORITY_TIME_CRITICAL` tells the Windows scheduler to avoid preempting this thread unless absolutely necessary. This reduces context switches that would pollute the timing measurements.

### 7.2 Cache and TLB Warming

The warm-up loop performs 100 dummy timing measurements before collecting real data. This serves multiple purposes:

**CPU Frequency Stabilization:** Modern CPUs use dynamic frequency scaling (Intel Turbo Boost, AMD Precision Boost). The CPU may initially run at a low frequency and ramp up when workload is detected. The warm-up loop triggers frequency scaling before real measurements begin.

**Cache Hierarchy Warming:** The first few memory accesses to the timing code itself will miss in cache. By the 100th iteration, the code is hot in L1 cache, eliminating instruction fetch latency from measurements.

**TLB Warming:** The page table entries for the measurement code and data are loaded into the TLB during warm-up, preventing TLB misses during actual measurements.

**Branch Predictor Training:** The CPU's branch predictor learns the measurement loop's control flow, reducing branch misprediction penalties.

Without warm-up, the first few measurements exhibit timings 2-3x higher than steady-state, completely skewing the statistical analysis.

---

## 8. Practical Deployment and Results

### 8.1 Hardware Test Configuration

All testing was conducted on a single hardware platform:

- **CPU:** Intel Core i7-9750H (Coffee Lake-H, 6 cores, 12 threads)
- **Base Frequency:** 2.6 GHz
- **Turbo Frequency:** 4.5 GHz (single core), 4.0 GHz (all cores)
- **Cache:** 32KB L1D per core, 256KB L2 per core, 12MB L3 shared
- **TDP:** 45W
- **System:** Dell XPS 7590
- **RAM:** 32GB DDR4-2666
- **OS:** Windows 10/11 Pro (tested on both)

The i7-9750H represents Intel's high-performance mobile architecture from 2019. It features aggressive out-of-order execution, speculative prefetching, and a deep branch prediction pipeline - characteristics that make it susceptible to timing side-channels.

### 8.2 Success Rate and Reliability

Across 50 consecutive test runs on the i7-9750H configuration:

- **Successful leaks:** 50/50 (100%)
- **Average execution time:** 8.3 seconds
- **Leaked address variance:** 0 (all runs returned identical address)
- **Verification:** All leaked addresses matched actual kernel base (confirmed via kernel debugging)

The 100% success rate reflects both the microarchitectural vulnerability and the effectiveness of the statistical noise filtering. The zero variance in leaked addresses demonstrates that the voting mechanism successfully eliminates noise - every successful run converged to the same answer.

Execution time varied from 6.2 to 12.1 seconds depending on system load and thermal conditions. The voting mechanism typically achieved consensus in 4-5 attempts, rarely requiring all 7.

### 8.3 Comparison with Ground Truth

To verify accuracy, the leaked kernel base was compared against the actual kernel base obtained through legitimate means (kernel debugger attachment, reading the `KUSER_SHARED_DATA` structure, etc.).

Example run output:
```
Processor: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
Attempt 1/7: 0xFFFFF80245C00000 (votes: 1)
Attempt 2/7: 0xFFFFF80245C00000 (votes: 2)
Attempt 3/7: 0xFFFFF80245C00000 (votes: 3)
Attempt 4/7: 0xFFFFF80245C00000 (votes: 4)
Consensus reached: 0xFFFFF80245C00000 with 4/4 votes
Kernel base: 0xFFFFF80245C00000

Actual kernel base (verified): 0xFFFFF80245C00000
Match: TRUE
```

The leaked address matches the actual kernel base exactly, confirming the technique's precision.

### 8.4 Failure Modes and Edge Cases

While the implementation achieves 100% reliability on the test hardware, several failure modes exist in theory:

**High System Load:** If the CPU is saturated with other work, context switches and cache contention increase noise to the point where signal may be undetectable. The voting mechanism helps but cannot overcome arbitrary noise levels.

**Thermal Throttling:** If the CPU reaches thermal limits and throttles frequency mid-measurement, timing characteristics change dramatically. The implementation does not detect this condition.

**Virtualization:** Virtual machines introduce additional timing noise through hypervisor intervention. The technique may fail or exhibit reduced reliability in virtualized environments.

**Future Microarchitectures:** Intel and AMD continuously evolve their CPU designs. Future microarchitectures may implement timing-resistant prefetch mechanisms or more aggressive side-channel mitigations.

---

## 9. The AMD Uncertainty

### 9.1 Theoretical Implementation Without Hardware

The AMD-specific implementation in this codebase represents educated hypothesis rather than empirically validated technique. AMD processors exhibit different timing characteristics than Intel, but without access to AMD hardware for testing, the implementation relies on architectural documentation and reverse-engineering of published research.

The AMD leak implementation assumes:

1. Mapped kernel pages exhibit HIGHER prefetch timing
2. The timing differential is approximately 2:1 (mapped:unmapped)
3. Bimodal distribution analysis can separate signal from noise

These assumptions are based on documented differences in AMD's Zen microarchitecture:

- More conservative speculative execution bounds checking
- Different prefetch predictor algorithms
- Smaller TLB structures with different replacement policies

However, the actual timing characteristics on real AMD hardware remain unverified. The code may require significant tuning or may fail entirely on AMD systems.

### 9.2 AMD Mobile Complexity

AMD mobile processors (Ryzen Mobile series) introduce additional complexity through aggressive power management:

- More aggressive frequency scaling
- Core parking and unparking
- NUMA (Non-Uniform Memory Access) on multi-CCX designs
- Infinity Fabric latency variations

These factors create higher timing variance, making signal detection more challenging. The AMD Mobile implementation attempts to compensate through larger deviation thresholds:
```cpp
const int deviation_threshold = noise_signed / 6;
```

But without hardware validation, the effectiveness remains speculative.

### 9.3 Call for Community Validation

Researchers and enthusiasts with AMD hardware are encouraged to test the implementation and provide feedback. The GitHub repository welcomes pull requests with AMD-specific tuning and validated results.

The scientific method requires reproducibility. Until independent researchers confirm (or refute) the AMD implementation's effectiveness, it remains a hypothesis rather than validated technique.

---

## 10. Implications and Mitigations

### 10.1 The Limits of Software Mitigations

Cache timing attacks are fundamentally hardware vulnerabilities that cannot be completely mitigated in software. The microarchitectural state leakage occurs at a layer below the operating system's visibility.

Potential mitigations include:

**Address Space Layout Re-Randomization:** Re-randomize the kernel base periodically during runtime rather than once at boot. This limits the window of vulnerability but introduces performance overhead and complexity.

**Prefetch Instruction Filtering:** The CPU could refuse to execute prefetch instructions on unmapped addresses, always treating them as NOPs without MMU consultation. However, this would eliminate the performance benefit of prefetching in legitimate use cases.

**Constant-Time MMU Operations:** Design the MMU to perform page table walks in constant time regardless of whether the address is mapped. This is challenging because early-exit optimizations are critical for MMU performance.

**Noise Injection:** Intentionally add random delays to MMU operations to obscure timing differences. This degrades overall system performance for marginal security benefit.

None of these mitigations are currently implemented in mainstream CPUs or operating systems.

### 10.2 The Exploit Chain Requirement

It is critical to emphasize that leaking the kernel base address alone does not constitute a complete exploit. KASLR bypass is a single step in a larger attack chain that typically requires:

1. Initial vulnerability (buffer overflow, use-after-free, etc.)
2. KASLR bypass (this technique)
3. ROP chain construction or code injection
4. Privilege escalation
5. Payload execution

Each step faces additional mitigations (DEP, CFG, SMEP, SMAP, etc.). Defeating modern OS security requires bypassing multiple layers of defense.

However, KASLR bypass remains valuable to attackers because it eliminates randomization uncertainty. Many vulnerabilities are only exploitable with knowledge of kernel addresses. This research demonstrates that KASLR provides less protection than commonly assumed.

### 10.3 Responsible Disclosure

The techniques described here exploit documented CPU behavior rather than undisclosed vulnerabilities. Intel and AMD are aware that timing side-channels exist in their microarchitectures - this is an inherent consequence of performance-optimizing designs.

No vendor-specific vulnerabilities were discovered during this research. The implementation uses only publicly documented instructions (`prefetch`, `rdtscp`) and standard timing analysis techniques.

The code is released for educational and research purposes. Security researchers can use it to assess the effectiveness of KASLR in their environments. Defensive teams can use it to validate detection mechanisms for side-channel attacks.

---

## 11. Future Research Directions

### 11.1 Cross-Architecture Validation

The most critical next step is validation across diverse CPU architectures:

- Intel 10th, 11th, 12th, 13th, 14th generation (Comet Lake through Meteor Lake)
- AMD Zen 3, Zen 4, Zen 5 (Ryzen 5000/7000/9000 series)
- ARM64 (Qualcomm Snapdragon, Apple M-series under Windows on ARM)

Each architecture may exhibit unique timing characteristics requiring specialized implementations.

### 11.2 Hypervisor and Cloud Environments

Modern cloud computing relies heavily on virtualization. The interaction between cache timing attacks and hypervisor virtualization remains understudied:

- Do hypervisor TLB flushes on VM context switches eliminate timing signatures?
- Does hardware-assisted virtualization (Intel VT-x, AMD-V) introduce detectable timing artifacts?
- Can timing side-channels leak information across VM boundaries?

These questions have significant implications for cloud security.

### 11.3 Detection and Monitoring

Defensive research should focus on detecting side-channel attacks in progress:

- Can anomalous patterns of prefetch instructions be detected through performance counters?
- Do cache timing attacks create detectable CPU utilization signatures?
- Can machine learning models classify normal vs. attack timing behavior?

Performance monitoring units (PMUs) in modern CPUs provide rich telemetry that could potentially flag side-channel exploitation.

### 11.4 Microarchitectural Countermeasures

CPU vendors should investigate microarchitectural defenses:

- Randomized cache replacement policies
- Obfuscated MMU timing behavior
- Prefetch rate limiting for cross-privilege-boundary addresses
- Hardware-enforced constant-time page table walks

These defenses would impose performance costs but could eliminate entire classes of timing attacks.

---

## Building and Usage

### Prerequisites

- **Operating System:** Windows 10/11 (x64)
- **Compiler:** Visual Studio 2022 with C++20 support
- **Build Tools:** MASM (Microsoft Macro Assembler) for x64

### Building

1. Clone the repository:
```bash
git clone https://github.com/wesmar/KernelLeaker.git
cd KernelLeaker
```

2. Open `KernelLeaker.sln` in Visual Studio 2022

3. Build the solution:
   - Select **Release | x64** configuration
   - Build → Build Solution (Ctrl+Shift+B)

4. The compiled executable will be located in:
```
bin\x64\Release\KernelLeaker.exe
```

### Usage

Run the tool with administrator privileges for best results (though not strictly required):
```cmd
KernelLeaker.exe
```

This will attempt to leak the kernel base address and display the result.

**Print timing measurements:**
```cmd
KernelLeaker.exe --print-timings
```

or
```cmd
KernelLeaker.exe -pt
```

This displays raw timing data for all probed addresses, useful for debugging and analysis. Note that the `--print-timings` option shows the address with absolute minimum timing, but this is NOT the actual kernel base. The kernel base is typically 1MB (0x100000) before this minimum timing address, which is why the main leak function applies this correction automatically.

### Example Output

**Standard leak output:**
```
Processor: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
Absolute minimum: 60 cycles at 0xfffff806b4500000 (index: 27461)
Nearby addresses for verification:
  0xfffff806b4000000: 118 cycles
  0xfffff806b4100000: 111 cycles
  0xfffff806b4200000: 111 cycles
  0xfffff806b4300000: 111 cycles
  0xfffff806b4400000: 66 cycles
  0xfffff806b4500000: 60 cycles [MINIMUM]
  0xfffff806b4600000: 75 cycles
  0xfffff806b4700000: 60 cycles
  0xfffff806b4800000: 77 cycles
  0xfffff806b4900000: 60 cycles
  0xfffff806b4a00000: 76 cycles
  0xfffff806b4b00000: 60 cycles
  0xfffff806b4c00000: 89 cycles
  0xfffff806b4d00000: 60 cycles
  0xfffff806b4e00000: 76 cycles
Corrected kernel base: 0xfffff806b4400000 (original minimum: 0xfffff806b4500000)
Attempt 1/7: 0xfffff806b4400000 (votes: 1)
Attempt 2/7: 0xfffff806b4400000 (votes: 2)
Attempt 3/7: 0xfffff806b4400000 (votes: 3)
Attempt 4/7: 0xfffff806b4400000 (votes: 4)
Consensus reached: 0xfffff806b4400000 with 4/4 votes
Kernel base: 0xfffff806b4400000
```

**Timing dump output (`--print-timings`):**
```
fffff806b4000000 118
fffff806b4100000 111
fffff806b4200000 111
fffff806b4300000 111
fffff806b4400000 66
fffff806b4500000 60
fffff806b4600000 75
fffff806b4700000 60
...
fffff807fff00000 112
avg: 112
min: 60 at 0xfffff806b4500000
```

The timing dump shows the raw minimum address without the 1MB correction. To get the actual kernel base from timing dump output, subtract 0x100000 from the reported minimum address.

---

## Disclaimer

**Educational and Research Purposes Only**

This software is provided for educational and security research purposes only. The techniques demonstrated exploit documented CPU behavior and do not constitute exploitation of undisclosed vulnerabilities.

**No Warranty**

This software is provided "as is" without warranty of any kind, express or implied. The author makes no guarantees regarding:
- Accuracy of leaked addresses
- Reliability across different hardware configurations
- Compatibility with future OS or CPU updates
- Suitability for any particular purpose

**Responsible Use**

Users are responsible for ensuring their use of this software complies with applicable laws and regulations. Unauthorized access to computer systems is illegal in most jurisdictions.

**Hardware Limitations**

The implementation was tested exclusively on Intel i7-9750H. AMD-specific code is theoretical and unvalidated. Results on other CPU models may vary significantly.

**Not for Malicious Use**

This tool is intended to help security researchers understand microarchitectural vulnerabilities and assess KASLR effectiveness. It should not be used for malicious purposes or unauthorized system access.

---

## Contributing

Contributions are welcome, especially:

- **AMD Hardware Validation:** Testing and tuning on AMD Ryzen processors
- **Intel 12th+ Gen Testing:** Validation on Alder Lake and newer architectures
- **ARM64 Support:** Implementation for Windows on ARM
- **Detection Mechanisms:** Defensive techniques to identify side-channel attacks
- **Performance Optimizations:** Improvements to measurement speed or accuracy

Please submit pull requests with detailed descriptions of changes and test results.

---

## License

This project is released under the MIT License. See `LICENSE` file for details.

---

## Acknowledgments

This research builds upon decades of academic work in microarchitectural security. Special thanks to the broader security research community whose published work provided the theoretical foundation.

---

## Contact

**Marek Wesołowski**  
Low-Level Systems Programmer | Assembly, C, C++  
Research interests: Microarchitecture, OS Security, Side-Channel Analysis

Website: [https://kvc.pl](https://kvc.pl)

---

## Conclusion

This research demonstrates that KASLR on Windows x64 systems can be reliably defeated through cache timing side-channel attacks using only userspace code and documented CPU instructions. The technique achieves 100% success rate on Intel i7-9750H hardware through careful statistical analysis, microarchitectural understanding, and vendor-specific adaptation.

The fundamental vulnerability lies in the CPU's microarchitecture: prefetch instructions create measurable timing differences between mapped and unmapped kernel addresses. These differences, though small (30-80 CPU cycles), can be statistically isolated through repeated measurement, noise filtering, and consensus voting.

The implementation demonstrates several technical innovations:

- O(N) mode calculation replacing O(N²) nested loops
- Bimodal distribution separation for AMD processors
- Majority voting mechanism achieving 96%+ reliability from 80% per-attempt accuracy
- Vendor-specific timing signature adaptation (Intel vs AMD)
- Simplified minimum-finding approach for Intel processors

However, significant limitations remain. The technique was validated only on a single Intel CPU model. AMD-specific implementations remain theoretical without hardware validation. Newer CPU generations may prove more vulnerable, equally vulnerable, or more resistant - empirical data does not yet exist.

From a security perspective, this work reinforces that KASLR should not be considered a strong defense in isolation. It provides probabilistic protection against exploitation but can be deterministically bypassed through side-channel analysis. Defense-in-depth remains essential: KASLR must be combined with CFG, SMEP, SMAP, and other mitigations to provide meaningful security.

Microarchitectural side-channels represent a fundamental tension between performance and security. Modern CPUs achieve high performance through speculation, caching, and prefetching - the very mechanisms that create exploitable timing channels. As CPU designs evolve, this tension will only intensify.

The question is not whether side-channels exist - they are inevitable consequences of performance optimization. The question is how to build secure systems despite their existence. This research provides data for that discussion.

---

*Last updated: November 2025*# KernelLeaker
