#include "textflag.h"

TEXT ·directDaxCLWBRange(SB), NOSPLIT, $0-16
	MOVQ address+0(FP), AX
	MOVQ length+8(FP), CX
	ADDQ AX, CX
	ANDQ $-64, AX
clwb_loop:
	CMPQ AX, CX
	JBE clwb_done
	BYTE $0x66
	BYTE $0x0f
	BYTE $0xae
	BYTE $0x30
	ADDQ $64, AX
	JMP clwb_loop
clwb_done:
	BYTE $0x0f
	BYTE $0xae
	BYTE $0xf8
	RET

TEXT ·directDaxCLFlushOptRange(SB), NOSPLIT, $0-16
	MOVQ address+0(FP), AX
	MOVQ length+8(FP), CX
	ADDQ AX, CX
	ANDQ $-64, AX
clflushopt_loop:
	CMPQ AX, CX
	JBE clflushopt_done
	BYTE $0x66
	BYTE $0x0f
	BYTE $0xae
	BYTE $0x38
	ADDQ $64, AX
	JMP clflushopt_loop
clflushopt_done:
	BYTE $0x0f
	BYTE $0xae
	BYTE $0xf8
	RET

TEXT ·directDaxCLFlushRange(SB), NOSPLIT, $0-16
	MOVQ address+0(FP), AX
	MOVQ length+8(FP), CX
	ADDQ AX, CX
	ANDQ $-64, AX
clflush_loop:
	CMPQ AX, CX
	JBE clflush_done
	BYTE $0x0f
	BYTE $0xae
	BYTE $0x38
	ADDQ $64, AX
	JMP clflush_loop
clflush_done:
	BYTE $0x0f
	BYTE $0xae
	BYTE $0xf0
	RET
