/*
 *  linux/fs/fifo.c
 *
 *  written by Paul H. Hargrove
 *
 *  Fixes:
 *	10-06-1999, AV: fixed OOM handling in fifo_open(), moved
 *			initialization there, switched to external
 *			allocation of pipe_inode_info.
 */

#include <linux/mm.h>
#include <linux/malloc.h>
#include <linux/smp_lock.h>

static void wait_for_partner(struct inode* inode, unsigned int* cnt)
{
	int cur = *cnt;	
	while(cur == *cnt) {
		pipe_wait(inode);
		if(signal_pending(current))
			break;
	}
}

static void wake_up_partner(struct inode* inode)
{
	wake_up_interruptible(PIPE_WAIT(*inode));
}
//用于有名管道的打开
static int fifo_open(struct inode *inode, struct file *filp)
{
	int ret;

	ret = -ERESTARTSYS;
	lock_kernel();
	if (down_interruptible(PIPE_SEM(*inode)))
		goto err_nolock_nocleanup;

	if (!inode->i_pipe) {
		ret = -ENOMEM;
		if(!pipe_new(inode))
//首次打开时，该管道的缓冲区，尚未分配，所以分配一个pipe_inode_info构建缓冲区，以后再有打开同一个FIFO文件时
//，就可以跳过了
			goto err_nocleanup;
	}
	filp->f_version = 0;

	switch (filp->f_mode) {
	case 1:									//只读方式
	/*
	 *  O_RDONLY
	 *  POSIX.1 says that O_NONBLOCK means return with the FIFO
	 *  opened, even when there is no process writing the FIFO.
	 */
		filp->f_op = &read_fifo_fops;		//
		PIPE_RCOUNTER(*inode)++;
		if (PIPE_READERS(*inode)++ == 0)	//读者的个数为0
			wake_up_partner(inode);			//唤醒写者

		if (!PIPE_WRITERS(*inode)) {			//是否有写的资源
			if ((filp->f_flags & O_NONBLOCK)) {	//没有数据也不等待，并不阻塞。直接返回
				/* suppress POLLHUP until we have
				 * seen a writer */
				filp->f_version = PIPE_WCOUNTER(*inode);	//但是对写端增加计数
			} else 
			{
				wait_for_partner(inode, &PIPE_WCOUNTER(*inode)); //读端进入休眠	
				if(signal_pending(current))
					goto err_rd;
			}
		}
		break;
	
	case 2:
	/*
	 *  O_WRONLY
	 *  POSIX.1 says that O_NONBLOCK means return -1 with
	 *  errno=ENXIO when there is no process reading the FIFO.
	 */
		ret = -ENXIO;
		if ((filp->f_flags & O_NONBLOCK) && !PIPE_READERS(*inode))
			goto err;

		filp->f_op = &write_fifo_fops;
		PIPE_WCOUNTER(*inode)++;
		if (!PIPE_WRITERS(*inode)++)
			wake_up_partner(inode);

		if (!PIPE_READERS(*inode)) {
			wait_for_partner(inode, &PIPE_RCOUNTER(*inode));
			if (signal_pending(current))
				goto err_wr;
		}
		break;
	
	case 3:
	/*
	 *  O_RDWR
	 *  POSIX.1 leaves this case "undefined" when O_NONBLOCK is set.
	 *  This implementation will NEVER block on a O_RDWR open, since
	 *  the process can at least talk to itself.
	 */
		filp->f_op = &rdwr_fifo_fops;

		PIPE_READERS(*inode)++;
		PIPE_WRITERS(*inode)++;
		PIPE_RCOUNTER(*inode)++;
		PIPE_WCOUNTER(*inode)++;
		if (PIPE_READERS(*inode) == 1 || PIPE_WRITERS(*inode) == 1)
			wake_up_partner(inode);
		break;

	default:
		ret = -EINVAL;
		goto err;
	}

	/* Ok! */
	up(PIPE_SEM(*inode));
	unlock_kernel();
	return 0;

err_rd:
	if (!--PIPE_READERS(*inode))
		wake_up_interruptible(PIPE_WAIT(*inode));
	ret = -ERESTARTSYS;
	goto err;

err_wr:
	if (!--PIPE_WRITERS(*inode))
		wake_up_interruptible(PIPE_WAIT(*inode));
	ret = -ERESTARTSYS;
	goto err;

err:
	if (!PIPE_READERS(*inode) && !PIPE_WRITERS(*inode)) {
		struct pipe_inode_info *info = inode->i_pipe;
		inode->i_pipe = NULL;
		free_page((unsigned long)info->base);
		kfree(info);
	}

err_nocleanup:
	up(PIPE_SEM(*inode));

err_nolock_nocleanup:
	unlock_kernel();
	return ret;
}

/*
 * Dummy default file-operations: the only thing this does
 * is contain the open that then fills in the correct operations
 * depending on the access mode of the file...
 */
struct file_operations def_fifo_fops = {
	open:		fifo_open,	/* will set read or write pipe_fops */
};
