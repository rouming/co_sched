/*
 * co_sched - preemptive multitasking in userspace based on a SIGALRM signal
 *
 *   Copyright (C) 2016 Roman Pen <r.peniaev@gmail.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Description:
 *   This is a small experiment, an application, which starts 3 sorting
 *   routines, execution of each is preempted by SIGALRM signal, simulating
 *   an OS timer interrupt.  Each routine is an execution context, which
 *   can do a voluntary scheduling (calling schedule() directly) or be
 *   preempted by a timer, and in that case nonvoluntary scheduling occurs.
 *
 *   The default time slice is 10ms, that means that each 10ms SIGALRM fires
 *   and next context is scheduled by round robin algorithm.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <memory.h>
#include <ucontext.h>
#include <assert.h>
#include "list.h"

/* #define DEBUG */

#define BUILD_BUG_ON(condition) ((void )sizeof(char [1 - 2*!!(condition)]))

typedef _Bool bool;
enum {
	false	= 0,
	true	= 1
};

int preempt_count;

static void preempt_disable(void)
{
	assert(preempt_count >= 0);
	preempt_count++;
}

static void preempt_enable(void)
{
	assert(preempt_count > 0);
	preempt_count--;
}

static void local_irq_save(sigset_t *sig_set)
{
	sigset_t block_set;

	sigfillset(&block_set);
	sigdelset(&block_set, SIGINT);
	sigprocmask(SIG_BLOCK, &block_set, sig_set);
}

static void local_irq_restore(sigset_t *sig_set)
{
	sigprocmask(SIG_SETMASK, sig_set, NULL);
}

#define co_printf(...) ({	\
	preempt_disable();	\
	printf(__VA_ARGS__);	\
	preempt_enable();	\
})

typedef void (co_func)(void *arg);

struct co_struct {
	struct list_head co_list;
	ucontext_t co_ctx;
	void	*co_stack;
	co_func *co_func;
	void	*co_arg;
	bool     co_reapme;
};

static struct co_struct *co_current;
static struct co_struct	 co_main;
static LIST_HEAD(co_reap);

static void co_init(void)
{
	INIT_LIST_HEAD(&co_main.co_list);
	co_current = &co_main;
}

static struct co_struct *co_alloc(co_func *func, void *arg)
{
	struct co_struct *co;

	co = calloc(1, sizeof(*co));
	assert(co);
	co->co_stack = calloc(1, 1<<20);
	assert(co->co_stack);

#ifdef DEBUG
	co_printf(">> co_alloc: %s, co=%p sp=%p\n",
		  (char *)arg, co, co->co_stack);
#endif

	co->co_func = func;
	co->co_arg = arg;

	return co;
}

static void co_destroy(struct co_struct *co)
{
	assert(co != &co_main);
	list_del(&co->co_list);
	free(co->co_stack);
	free(co);
}

static void co_clean_reaps(void)
{
	struct co_struct *co, *tmp;

	list_for_each_entry_safe(co, tmp, &co_reap, co_list)
		co_destroy(co);
}

static void co_switch_to(struct co_struct *from, struct co_struct *to)
{
	co_current = to;
#ifdef DEBUG
	co_printf(">> switch: %p (ip=0x%llx, sp=0x%llx) -> %p (ip=0x%llx, sp=0x%llx)\n",
		  from,
		  from->co_ctx.uc_mcontext.gregs[REG_RIP],
		  from->co_ctx.uc_mcontext.gregs[REG_RSP],
		  to,
		  to->co_ctx.uc_mcontext.gregs[REG_RIP],
		  to->co_ctx.uc_mcontext.gregs[REG_RSP]
		);
#endif
	swapcontext(&from->co_ctx, &to->co_ctx);
}

void schedule(void)
{
	sigset_t set;
	struct co_struct *next_co;

	assert(co_current);
	assert(preempt_count == 0);
	local_irq_save(&set);
	next_co = list_first_entry_or_null(&co_current->co_list,
					   struct co_struct, co_list);
	if (next_co) {
		if (co_current->co_reapme)
			list_move(&co_current->co_list, &co_reap);
		co_switch_to(co_current, next_co);
	} else {
		assert(co_current == &co_main);
		assert(co_current->co_reapme == false);
	}
	co_clean_reaps();
	local_irq_restore(&set);
}

union co_ptr {
	void *p;
	int i[2];
};

__attribute__ ((noreturn))
static void co_trampoline(int i0, int i1)
{
	union co_ptr ptr = {
		.i = { i0, i1 }
	};
	struct co_struct *co = ptr.p;

	co->co_func(co->co_arg);
	co->co_reapme = true;
	schedule();
	assert(0);
	__builtin_unreachable();
}

static void co_add(co_func *func, void *param)
{
	struct co_struct *co;
	union co_ptr ptr;

	co = co_alloc(func, param);
	assert(co);

	if (getcontext(&co->co_ctx) == -1)
		abort();
	co->co_ctx.uc_stack.ss_sp = co->co_stack;
	co->co_ctx.uc_stack.ss_size = 1<<20;
	co->co_ctx.uc_stack.ss_flags = 0;
	co->co_ctx.uc_link = NULL;

	ptr.p = co;
	makecontext(&co->co_ctx, (void (*)(void))co_trampoline,
		    2, ptr.i[0], ptr.i[1]);
	preempt_disable();
	list_add_tail(&co->co_list, &co_main.co_list);
	preempt_enable();
}

static void timer_handler(int signo, siginfo_t *info, ucontext_t *ctx)
{
#ifdef DEBUG
	printf("@@@@ timer: ip=0x%llx, sp=0x%llx\n",
	       ctx->uc_mcontext.gregs[REG_RIP],
	       ctx->uc_mcontext.gregs[REG_RSP]);
#endif

	/* Do nothing. Preemption disabled */
	if (preempt_count) {
		return;
	}

	/* We can schedule directly from sighandler, because kernel
	 * cares only about proper sigreturn frame in the stack */
	schedule();
}

static void timer_init(void)
{
	struct sigaction sa;

	sa.sa_handler = (void (*)(int))&timer_handler;
	sa.sa_flags = SA_SIGINFO;
	sigfillset(&sa.sa_mask);
	sigaction(SIGALRM, &sa, NULL);
}

static void timer_create(unsigned int usecs)
{
	ualarm(usecs, usecs);
}

static void timer_cancel(void)
{
	ualarm(0, 0);
}

static void timer_wait(void)
{
	sigset_t mask;

	sigprocmask(0, NULL, &mask);
	sigdelset(&mask, SIGALRM);
	sigsuspend(&mask);
}

#define ARR_SZ 10000000

static int cmpint(const void *a, const void *b, void *arg)
{
	return *(int *)a - *(int *)b;
}

static void test_sort(void *arg)
{
	int *a, i, r = 1;
	char *name = arg;

	preempt_disable();
	a = malloc(ARR_SZ * sizeof(int));
	preempt_enable();
	assert(a);

	co_printf("[%s] %s: begin init, a=%p\n", name, __func__, a);

	for (i = 0; i < ARR_SZ; i++) {
		r = (r * 725861) % 6599;
		a[i] = r;
	}

	co_printf("[%s] %s: start sort\n", name, __func__);

	qsort_r(a, ARR_SZ, sizeof(int), cmpint, name);

	for (i = 0; i < ARR_SZ - 1; i++)
		if (a[i] > a[i+1]) {
			co_printf("[%s] sort() failed: a[%d]=%d, a[%d]=%d\n",
				  name, i, a[i], i + 1, a[i + 1]);
			assert(0);
		}

	co_printf("[%s] %s: end\n", name, __func__);

	preempt_disable();
	free(a);
	preempt_enable();
}

int main()
{
	timer_init();
	co_init();

	co_add(test_sort, "1");
	co_add(test_sort, "2");
	co_add(test_sort, "3");

	printf("~~~~ let's rock!\n");

	preempt_disable();
	timer_create(10000);

	/* Loop */
	while (!list_empty(&co_main.co_list) ||
	       !list_empty(&co_reap)) {
		preempt_enable();
		timer_wait();
		preempt_disable();
	}
	preempt_enable();
	timer_cancel();

	printf("~~~~ i am done\n");

	return 0;
}
