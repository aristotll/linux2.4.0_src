#ifndef __LINUX_NET_SCM_H
#define __LINUX_NET_SCM_H

/* Well, we should have at least one descriptor open
 * to accept passed FDs 8)
 */
#define SCM_MAX_FD	(OPEN_MAX-1)

struct scm_fp_list
{
	int		count;
	struct file	*fp[SCM_MAX_FD];
};

//接收的附加信息
struct scm_cookie
{
	struct ucred		creds;		/* Skb credentials	*/		//对方的身份
	struct scm_fp_list	*fp;		/* Passed files		*/			
	unsigned long		seq;		/* Connection seqno	*/
};


//unix_dgram_recvmsg

extern void scm_detach_fds(struct msghdr *msg, struct scm_cookie *scm);
extern int __scm_send(struct socket *sock, struct msghdr *msg, struct scm_cookie *scm);
extern void __scm_destroy(struct scm_cookie *scm);
extern struct scm_fp_list * scm_fp_dup(struct scm_fp_list *fpl);

static __inline__ void scm_destroy(struct scm_cookie *scm)
{
	if (scm && scm->fp)
		__scm_destroy(scm);
}

static __inline__ int scm_send(struct socket *sock, struct msghdr *msg,
			       struct scm_cookie *scm)
{
	memset(scm, 0, sizeof(*scm));
	scm->creds.uid = current->uid;
	scm->creds.gid = current->gid;
	scm->creds.pid = current->pid;
	if (msg->msg_controllen <= 0)
		return 0;
	return __scm_send(sock, msg, scm);
}

//对接收到的附加信息的处理
static __inline__ void scm_recv(struct socket *sock, struct msghdr *msg,
				struct scm_cookie *scm, int flags)
{
	if (!msg->msg_control)		//首先如果附加进程中没有控制信息时
	{
		if (sock->passcred || scm->fp)
			msg->msg_flags |= MSG_CTRUNC;
		scm_destroy(scm);			//那就直接把scm_cookie给销毁掉
		return;
	}

	if (sock->passcred)
		put_cmsg(msg, SOL_SOCKET, SCM_CREDENTIALS, sizeof(scm->creds), &scm->creds);
	//将有关的附加信息提交到用户空间中去

	if (!scm->fp)
		return;
	
	scm_detach_fds(msg, scm);
	//如果包含有对已打开文件的访问权限，那就要把这些已打开文件纳入到接收进程的已打开文件表中
}


#endif __LINUX_NET_SCM_H

