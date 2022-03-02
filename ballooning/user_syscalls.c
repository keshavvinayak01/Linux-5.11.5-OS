#include <linux/capability.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/sched/user.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/mempolicy.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/export.h>
#include <linux/rmap.h>
#include <linux/mmzone.h>
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/sched/signal.h>
#include <asm/signal.h>
#include <asm/siginfo.h>
#include <linux/gfp.h>

#define malloc(a) kmalloc(a, GFP_KERNEL)

struct sigballoon_sub *sigb_head = NULL;
extern int vm_swappiness;

static int apply_mlockall_flags(struct task_struct *p, int flags)
{
	struct vm_area_struct * vma, * prev = NULL;
	vm_flags_t to_add = 0;

	// current->mm->def_flags &= VM_LOCKED_CLEAR_MASK;
	p->mm->def_flags &= VM_LOCKED_CLEAR_MASK;
	if (flags & MCL_FUTURE) {
		// current->mm->def_flags |= VM_LOCKED;
		p->mm->def_flags |= VM_LOCKED;

		if (flags & MCL_ONFAULT)
			// current->mm->def_flags |= VM_LOCKONFAULT;
			p->mm->def_flags |= VM_LOCKONFAULT;

		if (!(flags & MCL_CURRENT))
			goto out;
	}

	if (flags & MCL_CURRENT) {
		to_add |= VM_LOCKED;
		if (flags & MCL_ONFAULT)
			to_add |= VM_LOCKONFAULT;
	}

	// for (vma = current->mm->mmap; vma ; vma = prev->vm_next) {
	for (vma = p->mm->mmap; vma ; vma = prev->vm_next) {
		vm_flags_t newflags;

		newflags = vma->vm_flags & VM_LOCKED_CLEAR_MASK;
		newflags |= to_add;

		/* Ignore errors */
		mlock_fixup(vma, &prev, vma->vm_start, vma->vm_end, newflags);
		cond_resched();
	}
out:
	return 0;
}

static int _munlockall(struct task_struct *p)
{
	int ret;

	// if (mmap_write_lock_killable(current->mm))
	if (mmap_write_lock_killable(p->mm))
		return -EINTR;
	// ret = apply_mlockall_flags(0);
	// mmap_write_unlock(current->mm);
	ret = apply_mlockall_flags(p, 0);
	up_write(&p->mm->mmap_lock);

	return ret;
}

static int _mlockall(struct task_struct *p, int flags)
{
	unsigned long lock_limit;
	int ret;

	if (!flags || (flags & ~(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)) ||
	    flags == MCL_ONFAULT)
		return -EINVAL;

	if (!can_do_mlock())
		return -EPERM;

	lock_limit = rlimit(RLIMIT_MEMLOCK);
	lock_limit >>= PAGE_SHIFT;

	// if (mmap_write_lock_killable(current->mm))
	if (mmap_write_lock_killable(p->mm))
		return -EINTR;

	ret = -ENOMEM;
	// if (!(flags & MCL_CURRENT) || (current->mm->total_vm <= lock_limit) ||
	if (!(flags & MCL_CURRENT) || (p->mm->total_vm <= lock_limit) ||
	    capable(CAP_IPC_LOCK))
		ret = apply_mlockall_flags(p, flags);
	// mmap_write_unlock(current->mm);
	mmap_write_unlock(p->mm);
	if (!ret && (flags & MCL_CURRENT))
		mm_populate(0, TASK_SIZE);

	return ret;
}

static bool check_same_owner(struct task_struct *p)
{
	const struct cred *cred = current_cred(), *pcred;
	bool match;

	rcu_read_lock();

	pcred = __task_cred(p);
	match = (uid_eq(cred->euid, pcred->euid) ||
	uid_eq(cred->euid, pcred->uid));

	rcu_read_unlock();
	return match;
}

/*
Check the permission to exec the mlockall_pid and munlockall_pid and write
the struct corresponding to the pid provided.
*/

static int check_and_get_process(pid_t pid, struct task_struct **p)
{
	*p = NULL;
	if (pid < 0)
		return -EINVAL;

	if (pid == 0) {
		*p = current;
		return 0;
	}

	rcu_read_lock();
	*p = find_task_by_vpid(pid);

	if (*p == NULL) {
		rcu_read_unlock();
		return -ESRCH;
	}

	if ((*p)->flags & PF_KTHREAD)  {
		rcu_read_unlock();
		return -EINVAL;
	}

	// Prevent p going away
	get_task_struct(*p);
	rcu_read_unlock();

	if (!check_same_owner(*p) && !capable(CAP_IPC_LOCK)) {
		put_task_struct(*p);
		return -EPERM;
	}

	return 0;
}

SYSCALL_DEFINE2(mlockall_pid, pid_t, pid, int, flags)
{
	int ret;
	struct task_struct *p;

	ret = check_and_get_process(pid, &p);

	if(ret)
		return ret;

	ret = _mlockall(p, flags);

	if(p != current)
		put_task_struct(p);

	return ret;
}
SYSCALL_DEFINE1(mlockfull, int, flags)
{
	// Set vm_swappiness to 0 to prevent swapping as long as possible
	vm_swappiness = 0;
	// First lock all the user application pages in the memory to prevent swap.	
	struct task_struct *task_list;
	// struct kernel_siginfo info;
	bool found_sigb_task = false;
	struct sigballoon_sub *newsub = (struct sigballoon_sub*) malloc(sizeof(struct sigballoon_sub));
	struct sigballoon_sub *check = sigb_head;
	int ret;
	// check if process has already requested mlock, should not be added to balloon_list again.
	while(check && check->task) {
		if(check->task == current) {
			found_sigb_task = true;
			break;
		}
		check = check->next;
	}
	check = NULL;
	if(!found_sigb_task) {
		newsub->task = current;
		newsub->next = sigb_head;
		sigb_head = newsub;
		newsub = NULL;
	}
	for_each_process(task_list) {
		if(!(task_list->parent->pid <= 2) && task_list != current) 
		{
			printk("Locked! : %s, %ld, %d\n", task_list->comm, task_list->state, task_list->pid);
			ret = _mlockall(task_list, flags);
		}
		// Some error occurred.
		if(ret) return ret;
	}
	printk("Locking pages completed!\n");
	return ret;
}

SYSCALL_DEFINE0(munlockfull)
{
	// Set swappiness back to 60
	vm_swappiness = 60;
	// First lock all the user application pages in the memory to prevent swap.	
	struct task_struct *task_list;
	struct sigballoon_sub *curr = sigb_head;
	struct sigballoon_sub *curr_prev = sigb_head;
	bool found_sigb_proc = false;
	int ret = 0;
	// check if process has already requested mlock, should not be added to balloon_list again.
	if(!sigb_head) {
		printk("No Process registered for SIGBALLOON\n");
		return 0;
	}

	else if(sigb_head->task == current) {
		found_sigb_proc = true;
		sigb_head = sigb_head->next;
		curr->task = NULL;
		curr->next = NULL;
	}
	else {
		while(curr) {
			if(curr->task == current) {
				found_sigb_proc = true;
				curr_prev->next->next = curr->next;
				curr->task = NULL;
				curr->next = NULL;			
				break;
			}
			curr_prev = curr;
			curr = curr->next;
		}	
	}
	if(found_sigb_proc) {
		for_each_process(task_list) {
			if(!(task_list->parent->pid <= 2) && task_list != current) 
			{
				printk("Unlocked! : %s, %ld, %d\n", task_list->comm, task_list->state, task_list->pid);
				ret = _munlockall(task_list);
			}
			// Some error occurred.
			if(ret) return ret;
		}
		printk("Unlocked all locked pages!\n");
	}
	return ret;
}

SYSCALL_DEFINE1(munlockall_pid, pid_t, pid)
{
	int ret;
	struct task_struct *p;

	ret = check_and_get_process(pid, &p);

	if(ret)
		return ret;

	ret = _munlockall(p);

	if(p != current)
		put_task_struct(p);

	return ret;
}