/*
 *	linux/kernel/softirq.c
 *
 *	Copyright (C) 1992 Linus Torvalds
 *
 * Fixed a disable_bh()/enable_bh() race (was causing a console lockup)
 * due bh_mask_count not atomic handling. Copyright (C) 1998  Andrea Arcangeli
 *
 * Rewritten. Old one was good in 2.2, but in 2.3 it was immoral. --ANK (990903)
 */

#include <linux/config.h>
#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/tqueue.h>

/*
   - No shared variables, all the data are CPU local.
   - If a softirq needs serialization, let it serialize itself
     by its own spinlocks.
   - Even if softirq is serialized, only local cpu is marked for
     execution. Hence, we get something sort of weak cpu binding.
     Though it is still not clear, will it result in better locality
     or will not.
   - These softirqs are not masked by global cli() and start_bh_atomic()
     (by clear reasons). Hence, old parts of code still using global locks
     MUST NOT use softirqs, but insert interfacing routines acquiring
     global locks. F.e. look at BHs implementation.

   Examples:
   - NET RX softirq. It is multithreaded and does not require
     any global serialization.
   - NET TX softirq. It kicks software netdevice queues, hence
     it is logically serialized per device, but this serialization
     is invisible to common code.
   - Tasklets: serialized wrt itself.
   - Bottom halves: globally serialized, grr...
 */

/* No separate irq_stat for s390, it is part of PSA */
#if !defined(CONFIG_ARCH_S390)
irq_cpustat_t irq_stat[NR_CPUS];
#endif	/* CONFIG_ARCH_S390 */

static struct softirq_action softirq_vec[32] __cacheline_aligned;  //也设置了32个

//tasklet_action

//这个是tasklet_init初始化的
asmlinkage void do_softirq()  //执行软中断函数
{
	int cpu = smp_processor_id();
	__u32 active, mask;

	if (in_interrupt())  //不能在一个硬中断服务程序中运行，也不能在一个软中断服务程序中运行
		return;

	//到这里，不同的cpu是可以进入同一个软中断服务程序的，但是不能相互干扰

	local_bh_disable();

	local_irq_disable();

	mask = softirq_mask(cpu);
	
	active = softirq_active(cpu) & mask;

	if (active) {
		struct softirq_action *h;

restart:
		/* Reset active bitmask before enabling irqs */
		softirq_active(cpu) &= ~active;

		local_irq_enable();

		h = softirq_vec;
		mask &= ~active;

		do {
			if (active & 1)
				h->action(h);  //不同的cpu可以进入不同的bh	
			//bh_action
			//tasklet_action
			h++;
			active >>= 1;  //来移位
		} while (active);

		local_irq_disable();

		active = softirq_active(cpu);
		if ((active &= mask) != 0)
			goto retry;
	}

	local_bh_enable();

	/* Leave with locally disabled hard irqs. It is critical to close
	 * window for infinite recursion, while we help local bh count,
	 * it protected us. Now we are defenceless.
	 */
	return;

retry:
	goto restart;
}


static spinlock_t softirq_mask_lock = SPIN_LOCK_UNLOCKED;

//设置了一个以软件中断号为下标的数组softirq_vec[],类似于中断机制中的irq_desc
void open_softirq(int nr, void (*action)(struct softirq_action*), void *data)
{
	unsigned long flags;
	int i;


	tasklet_hi_vec
	spin_lock_irqsave(&softirq_mask_lock, flags);
	softirq_vec[nr].data = data;      //先送入对应的nr中的参数
	softirq_vec[nr].action = action;  //以及函数

	for (i=0; i<NR_CPUS; i++)
		softirq_mask(i) |= (1<<nr);   //把所有的CPU软中断屏蔽控制器中的nr设成了1
	spin_unlock_irqrestore(&softirq_mask_lock, flags);
}


/* Tasklets */

struct tasklet_head tasklet_vec[NR_CPUS] __cacheline_aligned;

//这个是open_softirq注册的
static void tasklet_action(struct softirq_action *a)
{
	int cpu = smp_processor_id();
	struct tasklet_struct *list;

	local_irq_disable();
	list = tasklet_vec[cpu].list;  //得到每一个tasklet_vec的链表
	tasklet_vec[cpu].list = NULL;
	local_irq_enable();

	while (list != NULL) {
		struct tasklet_struct *t = list;

		list = list->next;

		if (tasklet_trylock(t)) {
			if (atomic_read(&t->count) == 0) {
				clear_bit(TASKLET_STATE_SCHED, &t->state);

				t->func(t->data); //执行相应的函数
				/*
				 * talklet_trylock() uses test_and_set_bit that imply
				 * an mb when it returns zero, thus we need the explicit
				 * mb only here: while closing the critical section.
				 */
#ifdef CONFIG_SMP
				smp_mb__before_clear_bit();
#endif
				tasklet_unlock(t);
				continue;
			}
			tasklet_unlock(t);
		}
		local_irq_disable();
		t->next = tasklet_vec[cpu].list;
		tasklet_vec[cpu].list = t;
		__cpu_raise_softirq(cpu, TASKLET_SOFTIRQ);
		local_irq_enable();
	}
}




struct tasklet_head tasklet_hi_vec[NR_CPUS] __cacheline_aligned;
//每一个cpu都有这样的一个头，其实就是指向tasklet_struct
//


static void tasklet_hi_action(struct softirq_action *a)
{
	int cpu = smp_processor_id();
	struct tasklet_struct *list;

	local_irq_disable();
	list = tasklet_hi_vec[cpu].list;
	tasklet_hi_vec[cpu].list = NULL;
	local_irq_enable();

	while (list != NULL) {
		struct tasklet_struct *t = list;

		list = list->next;

		if (tasklet_trylock(t)) {
			if (atomic_read(&t->count) == 0) {
				clear_bit(TASKLET_STATE_SCHED, &t->state);

				t->func(t->data);
				tasklet_unlock(t);
				continue;
			}
			tasklet_unlock(t);
		}
		local_irq_disable();
		t->next = tasklet_hi_vec[cpu].list;
		tasklet_hi_vec[cpu].list = t;
		__cpu_raise_softirq(cpu, HI_SOFTIRQ);
		local_irq_enable();
	}
}


void tasklet_init(struct tasklet_struct *t,
		  void (*func)(unsigned long), unsigned long data)
{
	t->func = func;
	t->data = data;
	t->state = 0;
	atomic_set(&t->count, 0);
}

void tasklet_kill(struct tasklet_struct *t)
{
	if (in_interrupt())
		printk("Attempt to kill tasklet from interrupt\n");

	while (test_and_set_bit(TASKLET_STATE_SCHED, &t->state)) {
		current->state = TASK_RUNNING;
		do {
			current->policy |= SCHED_YIELD;
			schedule();
		} while (test_bit(TASKLET_STATE_SCHED, &t->state));
	}
	tasklet_unlock_wait(t);
	clear_bit(TASKLET_STATE_SCHED, &t->state);
}



/* Old style BHs */

static void (*bh_base[32])(void);
struct tasklet_struct bh_task_vec[32];

/* BHs are serialized by spinlock global_bh_lock.

   It is still possible to make synchronize_bh() as
   spin_unlock_wait(&global_bh_lock). This operation is not used
   by kernel now, so that this lock is not made private only
   due to wait_on_irq().

   It can be removed only after auditing all the BHs.
 */
spinlock_t global_bh_lock = SPIN_LOCK_UNLOCKED;
//down
static void bh_action(unsigned long nr)
{
	int cpu = smp_processor_id();

	//SMP是不能通过的  
	if (!spin_trylock(&global_bh_lock))  //控制只有单个cpu进入执行的
		goto resched;

	if (!hardirq_trylock(cpu))  //防止一个硬中断程序内部调用一个bh
		goto resched_unlock;

	if (bh_base[nr])   //执行放入的函数
		bh_base[nr]();

	hardirq_endlock(cpu);
	spin_unlock(&global_bh_lock);		
	return;

resched_unlock:
	spin_unlock(&global_bh_lock);
resched:
	mark_bh(nr);
}

//mark_bh
void init_bh(int nr, void (*routine)(void))
{
	bh_base[nr] = routine;  //根据nr，挂钩对应的具体的软中断服务程序, bh_base一个函数指针数组
	mb();   //与流水线有关
}

//mark_bh

void remove_bh(int nr)
{
	tasklet_kill(bh_task_vec+nr);
	bh_base[nr] = NULL;
}

//init_bh
void __init softirq_init()
{
	int i;

	for (i=0; i<32; i++)  //bh_task_vec是一个以tasklet的数组
		tasklet_init(bh_task_vec+i, bh_action, i);
	//先是将内核定义的tasklet_struct来进行初始化，函数执行全局的bh_action

	//先分别设置软中断向量中的两种
	open_softirq(TASKLET_SOFTIRQ, tasklet_action, NULL); //代表着一种称为tasklet的机制
	open_softirq(HI_SOFTIRQ, tasklet_hi_action, NULL);
}

init_bh
init_bh
void __run_task_queue(task_queue *list)
{
	struct list_head head, *next;
	unsigned long flags;

	spin_lock_irqsave(&tqueue_lock, flags);
	list_add(&head, list);
	list_del_init(list);
	spin_unlock_irqrestore(&tqueue_lock, flags);

	next = head.next;
	while (next != &head) {
		void (*f) (void *);
		struct tq_struct *p;
		void *data;

		p = list_entry(next, struct tq_struct, list);
		next = next->next;
		f = p->routine;
		data = p->data;
		wmb();
		p->sync = 0;
		if (f)
			f(data);
	}
}
