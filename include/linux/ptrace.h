#ifndef _LINUX_PTRACE_H
#define _LINUX_PTRACE_H
/* ptrace.h */
/* structs and defines to help the user use the ptrace system call. */

/* has the defines to get at the registers. */

#define PTRACE_TRACEME		   0	
#define PTRACE_PEEKTEXT		   1	//来读写被跟踪进程的指令空间
#define PTRACE_PEEKDATA		   2	
#define PTRACE_PEEKUSR		   3
#define PTRACE_POKETEXT		   4
#define PTRACE_POKEDATA		   5
#define PTRACE_POKEUSR		   6
#define PTRACE_CONT		   7
#define PTRACE_KILL		   8		//控制被跟踪进程的运行
#define PTRACE_SINGLESTEP	   9

#define PTRACE_ATTACH		0x10	//与被跟踪进程建立起联系
#define PTRACE_DETACH		0x11	//跟被跟踪进程离开关系

#define PTRACE_SYSCALL		  24

#include <asm/ptrace.h>
//sys_ptrace
#endif
