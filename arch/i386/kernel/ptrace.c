/* ptrace.c */
/* By Ross Biro 1/23/92 */
/*
 * Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/user.h>

#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/debugreg.h>

/*
 * does not yet catch signals sent when the child dies.
 * in exit.c or in signal.c.
 */

/* determines which flags the user has access to. */
/* 1 = access 0 = no access */
#define FLAG_MASK 0x00044dd5

/* set's the trap flag. */
#define TRAP_FLAG 0x100

/*
 * Offset of eflags on child stack..
 */
#define EFL_OFFSET ((EFL-2)*4-sizeof(struct pt_regs))

/*
 * this routine will get a word off of the processes privileged stack. 
 * the offset is how far from the base addr as stored in the TSS.  
 * this routine assumes that all the privileged stacks are in our
 * data space.
 */   
static inline int get_stack_long(struct task_struct *task, int offset)
{
	unsigned char *stack;

	stack = (unsigned char *)task->thread.esp0;
	stack += offset;
	return (*((int *)stack));
}

/*
 * this routine will put a word on the processes privileged stack. 
 * the offset is how far from the base addr as stored in the TSS.  
 * this routine assumes that all the privileged stacks are in our
 * data space.
 */
static inline int put_stack_long(struct task_struct *task, int offset,
	unsigned long data)
{
	unsigned char * stack;

	stack = (unsigned char *) task->thread.esp0;
	stack += offset;
	*(unsigned long *) stack = data;
	return 0;
}

static int putreg(struct task_struct *child,
	unsigned long regno, unsigned long value)
{
	switch (regno >> 2) {
		case FS:
			if (value && (value & 3) != 3)
				return -EIO;
			child->thread.fs = value;
			return 0;
		case GS:
			if (value && (value & 3) != 3)
				return -EIO;
			child->thread.gs = value;
			return 0;
		case DS:
		case ES:
			if (value && (value & 3) != 3)
				return -EIO;
			value &= 0xffff;
			break;
		case SS:
		case CS:
			if ((value & 3) != 3)
				return -EIO;
			value &= 0xffff;
			break;
		case EFL:
			value &= FLAG_MASK;
			value |= get_stack_long(child, EFL_OFFSET) & ~FLAG_MASK;
			break;
	}
	if (regno > GS*4)
		regno -= 2*4;
	put_stack_long(child, regno - sizeof(struct pt_regs), value);
	return 0;
}

static unsigned long getreg(struct task_struct *child,
	unsigned long regno)
{
	unsigned long retval = ~0UL;

	switch (regno >> 2) {
		case FS:
			retval = child->thread.fs;
			break;
		case GS:
			retval = child->thread.gs;
			break;
		case DS:
		case ES:
		case SS:
		case CS:
			retval = 0xffff;
			/* fall through */
		default:
			if (regno > GS*4)
				regno -= 2*4;
			regno = regno - sizeof(struct pt_regs);
			retval &= get_stack_long(child, regno);
	}
	return retval;
}

asmlinkage int sys_ptrace(long request, long pid, long addr, long data)
{
	struct task_struct *child;
	struct user * dummy = NULL;
	int i, ret;

	lock_kernel();
	ret = -EPERM;
	if (request == PTRACE_TRACEME) {	//请求
		/* are we already being traced? */
		if (current->ptrace & PT_PTRACED)
			goto out;
		/* set the ptrace bit in the process flags. */
		current->ptrace |= PT_PTRACED;	//设置当前进程的PT_PTRACED
		ret = 0;
		goto out;
	}
	ret = -ESRCH;
	read_lock(&tasklist_lock);
	child = find_task_by_pid(pid);		//根据进程号找到目标进程的task_struct
	if (child)
		get_task_struct(child);			//递增使用计数，主要是可能会发生调度，而使得task_struct的所在页面释放掉的可能
	read_unlock(&tasklist_lock);
	if (!child)
		goto out;

	ret = -EPERM;
	if (pid == 1)		/* you may not mess with init */	//是不允许跟踪init进程的
		goto out_tsk;

	if (request == PTRACE_ATTACH) {		
		if (child == current)			//自己不允许跟踪自己
			goto out_tsk;
		if ((!child->dumpable ||		//如果不是同一个用户或同一组，那就需要升级到特权用户
		    (current->uid != child->euid) ||
		    (current->uid != child->suid) ||
		    (current->uid != child->uid) ||
	 	    (current->gid != child->egid) ||
	 	    (current->gid != child->sgid) ||
	 	    (!cap_issubset(child->cap_permitted, current->cap_permitted)) ||
	 	    (current->gid != child->gid)) && !capable(CAP_SYS_PTRACE))
			goto out_tsk;
		/* the same process cannot be attached many times */
		if (child->ptrace & PT_PTRACED)			//必须是第一次被跟踪的
			goto out_tsk;
		child->ptrace |= PT_PTRACED;

		write_lock_irq(&tasklist_lock);
		if (child->p_pptr != current) {	//目标进程必须是当前进程的子进程
			REMOVE_LINKS(child);
			child->p_pptr = current;
			SET_LINKS(child);
		}
		write_unlock_irq(&tasklist_lock);

		send_sig(SIGSTOP, child, 1);	//向子进程发送SIGSTOP信号
		ret = 0;
		goto out_tsk;
	}
	ret = -ESRCH;
	if (!(child->ptrace & PT_PTRACED))	//后续的操作
		goto out_tsk;
	if (child->state != TASK_STOPPED) {
		if (request != PTRACE_KILL)
			goto out_tsk;
	}
	if (child->p_pptr != current)
		goto out_tsk;
	switch (request) {
	/* when I and D space are separate, these will need to be fixed. */
	case PTRACE_PEEKTEXT: /* read word at location addr. */		//从子进程的指令空间，读取一个长字
	case PTRACE_PEEKDATA: {	//从数据空间读取一个长字
		unsigned long tmp;
		int copied;

		copied = access_process_vm(child, addr, &tmp, sizeof(tmp), 0);
		ret = -EIO;
		if (copied != sizeof(tmp))
			break;
		ret = put_user(tmp,(unsigned long *) data);
		break;
	}

	//读取子进程在用户空间运行时，（进入系统空间前夕）的某个寄存器的内容
	/* read the word at location addr in the USER area. */
	case PTRACE_PEEKUSR: {
		unsigned long tmp;

		ret = -EIO;
		if ((addr & 3) || addr < 0 || 
		    addr > sizeof(struct user) - 3)
			break;

		tmp = 0;  /* Default return condition */
		if(addr < 17*sizeof(long))
			tmp = getreg(child, addr);		//读取寄存器的内容
		if(addr >= (long) &dummy->u_debugreg[0] &&
		   addr <= (long) &dummy->u_debugreg[7]){	//查看addr是否处于相应的量
			addr -= (long) &dummy->u_debugreg[0];
			addr = addr >> 2;
			tmp = child->thread.debugreg[addr];
		}
		ret = put_user(tmp,(unsigned long *) data);
		break;
	}

	/* when I and D space are separate, this will have to be fixed. */
	case PTRACE_POKETEXT: /* write the word at location addr. */
	case PTRACE_POKEDATA:	//将一个字写到一个位置
		ret = 0;
		if (access_process_vm(child, addr, &data, sizeof(data), 1) == sizeof(data))
			break;
		ret = -EIO;
		break;

	case PTRACE_POKEUSR: /* write the word at location addr in the USER area */
		ret = -EIO;
		if ((addr & 3) || addr < 0 || 
		    addr > sizeof(struct user) - 3)
			break;

		if (addr < 17*sizeof(long)) {
			ret = putreg(child, addr, data);
			break;
		}
		/* We need to be very careful here.  We implicitly
		   want to modify a portion of the task_struct, and we
		   have to be selective about what portions we allow someone
		   to modify. */

		  ret = -EIO;
		  if(addr >= (long) &dummy->u_debugreg[0] &&
		     addr <= (long) &dummy->u_debugreg[7]){

			  if(addr == (long) &dummy->u_debugreg[4]) break;
			  if(addr == (long) &dummy->u_debugreg[5]) break;
			  if(addr < (long) &dummy->u_debugreg[4] &&
			     ((unsigned long) data) >= TASK_SIZE-3) break;
			  
			  if(addr == (long) &dummy->u_debugreg[7]) {
				  data &= ~DR_CONTROL_RESERVED;
				  for(i=0; i<4; i++)
					  if ((0x5f54 >> ((data >> (16 + 4*i)) & 0xf)) & 1)
						  goto out_tsk;
			  }

			  addr -= (long) &dummy->u_debugreg;
			  addr = addr >> 2;
			  child->thread.debugreg[addr] = data;
			  ret = 0;
		  }
		  break;

	//分别用来事被跟踪的子进程在下一次系统调用时暂停或继续
	case PTRACE_SYSCALL: /* continue and stop at next (return from) syscall */
	case PTRACE_CONT: { /* restart after signal. */
		long tmp;

		ret = -EIO;
		if ((unsigned long) data > _NSIG)
			break;
		if (request == PTRACE_SYSCALL)
			child->ptrace |= PT_TRACESYS;
		else
			child->ptrace &= ~PT_TRACESYS;
		child->exit_code = data;
	/* make sure the single step bit is not set. */
		tmp = get_stack_long(child, EFL_OFFSET) & ~TRAP_FLAG;
		put_stack_long(child, EFL_OFFSET,tmp);
		wake_up_process(child);
		ret = 0;
		break;
	}

/*
 * make the child exit.  Best I can do is send it a sigkill. 
 * perhaps it should be put in the status that it wants to 
 * exit.
 */
	//使子进程推出运行
	case PTRACE_KILL: {
		long tmp;

		ret = 0;
		if (child->state == TASK_ZOMBIE)	/* already dead */
			break;
		child->exit_code = SIGKILL;
		/* make sure the single step bit is not set. */
		tmp = get_stack_long(child, EFL_OFFSET) & ~TRAP_FLAG;
		put_stack_long(child, EFL_OFFSET, tmp);
		wake_up_process(child);
		break;
	}

	//单步运行
	case PTRACE_SINGLESTEP: {  /* set the trap flag. */
		long tmp;

		ret = -EIO;
		if ((unsigned long) data > _NSIG)
			break;
		child->ptrace &= ~PT_TRACESYS;
		if ((child->ptrace & PT_DTRACE) == 0) {
			/* Spurious delayed TF traps may occur */
			child->ptrace |= PT_DTRACE;
		}
		tmp = get_stack_long(child, EFL_OFFSET) | TRAP_FLAG;
		put_stack_long(child, EFL_OFFSET, tmp);
		child->exit_code = data;
		/* give it a chance to run. */
		wake_up_process(child);
		ret = 0;
		break;
	}

	case PTRACE_DETACH: { /* detach a process that was attached. */
		long tmp;

		ret = -EIO;
		if ((unsigned long) data > _NSIG)
			break;
		child->ptrace = 0;
		child->exit_code = data;
		write_lock_irq(&tasklist_lock);
		REMOVE_LINKS(child);
		child->p_pptr = child->p_opptr;
		SET_LINKS(child);
		write_unlock_irq(&tasklist_lock);
		/* make sure the single step bit is not set. */
		tmp = get_stack_long(child, EFL_OFFSET) & ~TRAP_FLAG;
		put_stack_long(child, EFL_OFFSET, tmp);
		wake_up_process(child);
		ret = 0;
		break;
	}

	case PTRACE_GETREGS: { /* Get all gp regs from the child. */
	  	if (!access_ok(VERIFY_WRITE, (unsigned *)data, 17*sizeof(long))) {
			ret = -EIO;
			break;
		}
		for ( i = 0; i < 17*sizeof(long); i += sizeof(long) ) {
			__put_user(getreg(child, i),(unsigned long *) data);
			data += sizeof(long);
		}
		ret = 0;
		break;
	}

	case PTRACE_SETREGS: { /* Set all gp regs in the child. */
		unsigned long tmp;
	  	if (!access_ok(VERIFY_READ, (unsigned *)data, 17*sizeof(long))) {
			ret = -EIO;
			break;
		}
		for ( i = 0; i < 17*sizeof(long); i += sizeof(long) ) {
			__get_user(tmp, (unsigned long *) data);
			putreg(child, i, tmp);
			data += sizeof(long);
		}
		ret = 0;
		break;
	}

	case PTRACE_GETFPREGS: { /* Get the child FPU state. */
		if (!access_ok(VERIFY_WRITE, (unsigned *)data,
			       sizeof(struct user_i387_struct))) {
			ret = -EIO;
			break;
		}
		ret = 0;
		if ( !child->used_math ) {
			/* Simulate an empty FPU. */
			set_fpu_cwd(child, 0x037f);
			set_fpu_swd(child, 0x0000);
			set_fpu_twd(child, 0xffff);
		}
		get_fpregs((struct user_i387_struct *)data, child);
		break;
	}

	case PTRACE_SETFPREGS: { /* Set the child FPU state. */
		if (!access_ok(VERIFY_READ, (unsigned *)data,
			       sizeof(struct user_i387_struct))) {
			ret = -EIO;
			break;
		}
		child->used_math = 1;
		set_fpregs(child, (struct user_i387_struct *)data);
		ret = 0;
		break;
	}

	case PTRACE_GETFPXREGS: { /* Get the child extended FPU state. */
		if (!access_ok(VERIFY_WRITE, (unsigned *)data,
			       sizeof(struct user_fxsr_struct))) {
			ret = -EIO;
			break;
		}
		if ( !child->used_math ) {
			/* Simulate an empty FPU. */
			set_fpu_cwd(child, 0x037f);
			set_fpu_swd(child, 0x0000);
			set_fpu_twd(child, 0xffff);
			set_fpu_mxcsr(child, 0x1f80);
		}
		ret = get_fpxregs((struct user_fxsr_struct *)data, child);
		break;
	}

	case PTRACE_SETFPXREGS: { /* Set the child extended FPU state. */
		if (!access_ok(VERIFY_READ, (unsigned *)data,
			       sizeof(struct user_fxsr_struct))) {
			ret = -EIO;
			break;
		}
		child->used_math = 1;
		ret = set_fpxregs(child, (struct user_fxsr_struct *)data);
		break;
	}

	case PTRACE_SETOPTIONS: {
		if (data & PTRACE_O_TRACESYSGOOD)
			child->ptrace |= PT_TRACESYSGOOD;
		else
			child->ptrace &= ~PT_TRACESYSGOOD;
		ret = 0;
		break;
	}

	default:
		ret = -EIO;
		break;
	}
out_tsk:
	free_task_struct(child);
out:
	unlock_kernel();
	return ret;
}
//flush_tlb_others
asmlinkage void syscall_trace(void)
{
	if ((current->ptrace & (PT_PTRACED|PT_TRACESYS)) !=
			(PT_PTRACED|PT_TRACESYS))
		return;
	/* the 0x80 provides a way for the tracing parent to distinguish
	   between a syscall stop and SIGTRAP delivery */
	current->exit_code = SIGTRAP | ((current->ptrace & PT_TRACESYSGOOD)
					? 0x80 : 0);
	current->state = TASK_STOPPED;
	notify_parent(current, SIGCHLD);
	schedule();
	/*
	 * this isn't the same as continuing with a signal, but it will do
	 * for normal use.  strace only continues with a signal if the
	 * stopping signal is not SIGTRAP.  -brl
	 */
	if (current->exit_code) {
		send_sig(current->exit_code, current, 1);
		current->exit_code = 0;
	}
}
