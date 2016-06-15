#define __ASSEMBLY__
#ifndef ASM_NL
#define ASM_NL		 ;
#endif

#ifndef __ALIGN
#define __ALIGN		.align 4,0x90
#define __ALIGN_STR	".align 4,0x90"
#endif

#define ALIGN __ALIGN
#define ALIGN_STR __ALIGN_STR

#ifndef ENTRY
#define ENTRY(name) \
	.globl name ASM_NL \
	ALIGN ASM_NL \
	name:
#endif

#ifndef END
#define END(name) \
	.size name, .-name
#endif

#ifndef ENDPROC
#define ENDPROC(name) \
	.type name, @function ASM_NL \
	END(name)
#endif

#include <asm/unistd.h>
#include <asm-generic/signal-defs.h>
#define _NSIG8 8

ENTRY(nonvoluntary_schedule)
	pushf
	push %rax
	push %rcx
	push %rdx
	push %rsi
	push %rdi
	push %r8
	push %r9
	push %r10
	push %r11

	callq schedule

	/* oset */
	movq	$0x00, %rdx
	/* nset - on stack, see timer_handler() */
	leaq	0x58(%rsp), %rsi
	movl	$SIG_SETMASK, %edi
	movl	$_NSIG8,%r10d
	movl	$__NR_rt_sigprocmask, %eax
	syscall

	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rdi
	pop %rsi
	pop %rdx
	pop %rcx
	pop %rax
	popf

	/* Pop real stack of interrupted task */
	pop %rsp
	/* Jump to interrupted instruction */
	jmp *-0x88(%rsp)
ENDPROC(nonvoluntary_schedule)

/* Used for detecting that we are in a schedule */
ENTRY(nonvoluntary_schedule_end)
ENDPROC(nonvoluntary_schedule_end)
