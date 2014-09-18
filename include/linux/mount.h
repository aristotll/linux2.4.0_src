/*
 *
 * Definitions for mount interface. This describes the in the kernel build 
 * linkedlist with mounted filesystems.
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 * Version: $Id: mount.h,v 2.0 1996/11/17 16:48:14 mvw Exp mvw $
 *
 */
#ifndef _LINUX_MOUNT_H
#define _LINUX_MOUNT_H
#ifdef __KERNEL__

#define MNT_VISIBLE	1

//设备和目录节点用vfsmount作为链接点
//一个设备，device
struct vfsmount
{
	struct dentry *mnt_mountpoint;	/* dentry of mountpoint */  //指向安装点的dentry
	struct dentry *mnt_root;	/* root of the mounted tree */	//所安装设备上根目录的dentry
	struct vfsmount *mnt_parent;	/* fs we are mounted on */	//安装点所在设备当初安装的vfsmounts
	struct list_head mnt_instances;	/* other vfsmounts of the same fs */ //多个安装点到一个设备
	struct list_head mnt_clash;	/* those who are mounted on (other */	//链入到安装点的d_vfsmount中，多对1
					/* instances) of the same dentry */
	struct super_block *mnt_sb;	/* pointer to superblock */
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */		//链入到上一层的mnt_mounts队列中
	atomic_t mnt_count;
	int mnt_flags;
	char *mnt_devname;		/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	uid_t mnt_owner;
};

static inline struct vfsmount *mntget(struct vfsmount *mnt)
{
	if (mnt)
		atomic_inc(&mnt->mnt_count);
	return mnt;
}

static inline void mntput(struct vfsmount *mnt)
{
	if (mnt) {
		if (atomic_dec_and_test(&mnt->mnt_count))
			BUG();
	}
}

#endif
#endif /* _LINUX_MOUNT_H */
