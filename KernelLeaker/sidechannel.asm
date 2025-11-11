; High-precision timing measurements for cache side-channel analysis
; Uses RDTSCP for serializing time measurements and PREFETCH instructions
; to probe memory access latency differences between mapped/unmapped addresses

PUBLIC sidechannel
PUBLIC bad_syscall

_TEXT SEGMENT

; Measures CPU cycles consumed by prefetch operations on a given address
; This exploits timing differences in MMU behavior for mapped vs unmapped memory
; 
; Parameters:
;   RCX - Virtual address to probe
; Returns:
;   RAX - Elapsed CPU cycle count
sidechannel PROC
    push rbx
    push rsi
    push rdi
    mov rsi, rcx                    ; Preserve target address
    
    ; Establish timing baseline with full serialization
    mfence                          ; Wait for all memory operations
    rdtscp                          ; Read timestamp (serializing)
    mov r9, rax                     ; Save low 32 bits
    mov r8, rdx                     ; Save high 32 bits
    xor rax, rax                    ; Clear for clean state
    lfence                          ; Prevent speculative execution
    
    ; Execute prefetch operations - the actual probe
    ; PREFETCHNTA: Non-temporal (bypass L2 cache)
    ; PREFETCHT2: Low temporal locality (L3 cache)
    prefetchnta byte ptr [rsi]
    prefetcht2 byte ptr [rsi]
    
    ; Capture end timestamp
    lfence                          ; Serialize before measurement
    rdtscp                          ; Read ending timestamp
    mov rdi, rax
    mov rsi, rdx
    
    mfence                          ; Ensure completion
    
    ; Calculate elapsed cycles (64-bit arithmetic)
    mov rbx, r8
    shl rbx, 32
    or rbx, r9                      ; RBX = start timestamp
    
    mov rax, rsi
    shl rax, 32
    or rax, rdi                     ; RAX = end timestamp
    
    sub rax, rbx                    ; RAX = elapsed cycles
    
    pop rdi
    pop rsi
    pop rbx
    ret
sidechannel ENDP

; Triggers kernel transition to stabilize CPU state between measurements
; Uses invalid syscall number to force quick return from kernel mode
bad_syscall PROC
    mov rax, 99999                  ; Non-existent syscall number
    syscall
    ret
bad_syscall ENDP

_TEXT ENDS
END