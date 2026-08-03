#include "textflag.h"

// CLFLUSHOPT is weakly ordered. SFENCE completes every invalidation before
// control returns to Go and the mapped bytes are copied.
TEXT ·vnextReaderCLFlushOptRange(SB), NOSPLIT, $0-16
	MOVQ address+0(FP), AX
	MOVQ length+8(FP), CX
	ADDQ AX, CX
vnext_reader_clflushopt_loop:
	CMPQ AX, CX
	JBE vnext_reader_clflushopt_done
	BYTE $0x66
	BYTE $0x0f
	BYTE $0xae
	BYTE $0x38
	ADDQ $64, AX
	JMP vnext_reader_clflushopt_loop
vnext_reader_clflushopt_done:
	BYTE $0x0f
	BYTE $0xae
	BYTE $0xf8
	RET

// CLFLUSH is followed by MFENCE before the caller may copy from the mapping.
TEXT ·vnextReaderCLFlushRange(SB), NOSPLIT, $0-16
	MOVQ address+0(FP), AX
	MOVQ length+8(FP), CX
	ADDQ AX, CX
vnext_reader_clflush_loop:
	CMPQ AX, CX
	JBE vnext_reader_clflush_done
	BYTE $0x0f
	BYTE $0xae
	BYTE $0x38
	ADDQ $64, AX
	JMP vnext_reader_clflush_loop
vnext_reader_clflush_done:
	BYTE $0x0f
	BYTE $0xae
	BYTE $0xf0
	RET
