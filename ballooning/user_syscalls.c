#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/sched/user.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/mempolicy.h>
#include <linux/sched.h>
#include <linux/export.h>
#include <linux/rmap.h>
#include <linux/mmzone.h>
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/sched/signal.h>
#include <asm/signal.h>
#include <asm/current.h>
#include <asm/siginfo.h>
#include <linux/gfp.h>
#include <linux/syscalls.h>
#include <linux/swapfile.h>

#define malloc(a) kmalloc(a, GFP_KERNEL)
// Let max size be 1MB
#define MAX_SWAP 1024 * 1024
unsigned long pagebuf[MAX_SWAP];
struct sigballoon_sub *sigb_head = NULL;
pid_t swapnames[MAX_SWAPFILES];
int CUSTOM_SWAPOUT = 0;

extern int vm_swappiness;
extern unsigned int nr_swapfiles;

int is_sigb_proc(struct task_struct *proc) {
	if(sigb_head) {
		struct sigballoon_sub *check = sigb_head;
		while(check && check->task) {
			if(check->task == proc) {
				return 1;
			}
			check = check->next;
		}
	}
	return 0;
}

SYSCALL_DEFINE1(reg_sigballoon, int, flags)
{
	struct task_struct *task_list;
	struct sigballoon_sub *newsub = (struct sigballoon_sub*) malloc(sizeof(struct sigballoon_sub));
	int ret;
	vm_swappiness = 0;
	// check if process has already registered, should not be added to balloon_list again.
	
	if(!is_sigb_proc(current)) {
		newsub->task = current;
		newsub->next = sigb_head;
		sigb_head = newsub;
		newsub = NULL;
	}
	return ret;
}

SYSCALL_DEFINE0(unreg_sigballoon)
{
	// Set swappiness back to 60
	vm_swappiness = 60;
	// First lock all the user application pages in the memory to prevent swap.	
	struct task_struct *task_list;
	struct sigballoon_sub *curr = sigb_head;
	struct sigballoon_sub *curr_prev = sigb_head;
	int ret = 0;
	int found = 0;
	// check if process is registed to SIGBALLOON or not.
	if(!sigb_head) {
		printk("No Process registered for SIGBALLOON\n");
		return 0;
	}

	else if(sigb_head->task == current) {
		found = 1;
		sigb_head = sigb_head->next;
		curr->task = NULL;
		curr->next = NULL;
	}
	else {
		while(curr) {
			if(curr->task == current) {
				found = 1;
				curr_prev->next->next = curr->next;
				curr->task = NULL;
				curr->next = NULL;			
				break;
			}
			curr_prev = curr;
			curr = curr->next;
		}	
	}
	if(!found) {
		printk("Process not registed for SIGBALLOON\n");
	}
	return ret;
}

SYSCALL_DEFINE3(create_swapspace_pid, char __user*, swapfile, void __user *, start, size_t, size) 
{
	int ret;
	// Sanity check to see if swapfile was created!
	if(swapfile)
		printk("Kernel received swapfile name: %s\n", swapfile);
	else
		return -1;
	
	if(copy_from_user((void*)pagebuf, start, size))
		return -1;
	else {
		printk("Kernel VM creation succesful\n");
	}

	/* 
	* Now add page_list to the swapfile
	* https://www.kernel.org/doc/gorman/html/understand/understand014.html
	* 11.8  Activating a Swap Area [above]
	* Maintain a single swap space filemm/swapfile.c (line 77), of the registered sigballoon process.
	*/
	swapnames[nr_swapfiles] = current->pid;
 	CUSTOM_SWAPOUT = 1;
	ret = do_madvise(current->mm, (unsigned long)start, size, MADV_PAGEOUT);
	CUSTOM_SWAPOUT = 0;

	return ret;
}