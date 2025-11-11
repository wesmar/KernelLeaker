#pragma once

#include <cstdint>
#include <string>
#include <optional>
#include <array>
#include <format>

// Assembly-implemented timing primitives (C linkage required)
extern "C" {
    void bad_syscall();
    uint64_t sidechannel(void* ptr);
}

namespace kaslr {

    // Windows x64 kernel address space configuration
    // These bounds define the standard kernel mapping region
    namespace config {
        constexpr uint64_t KERNEL_LOWER_BOUND = 0xFFFF'F800'0000'0000ull;
        constexpr uint64_t KERNEL_UPPER_BOUND = 0xFFFF'F808'0000'0000ull;
        
        constexpr uint64_t SCAN_START = KERNEL_LOWER_BOUND;
        constexpr uint64_t SCAN_END = KERNEL_UPPER_BOUND;
        
        // Granularity of address space probing (1 MB steps)
        constexpr uint64_t STEP = 0x10'0000;
        
        // Expected number of consecutive mapped sections for kernel base
        constexpr size_t KERNEL_SECTIONS = 0xC;
        
        // Statistical sample size for timing measurements
        constexpr size_t ITERATIONS = 0x100;
        constexpr size_t DUMMY_ITERATIONS = 5;
        constexpr size_t TIMING_DIFF_THRESHOLD = 3;
        
        constexpr size_t ARRAY_SIZE = (SCAN_END - SCAN_START) / STEP;
    }

    // CPU vendor enumeration for architecture-specific leaking strategies
    enum class CpuVendor {
        Unknown,
        Intel,       // Standard Intel microarchitecture
        IntelN200,   // Intel N-series (Alder Lake-N) - different cache behavior
        Amd,         // AMD desktop (Zen)
        AmdMobile    // AMD mobile (Zen with aggressive power management)
    };

    std::string cpu_vendor_to_string(CpuVendor vendor);

} // namespace kaslr