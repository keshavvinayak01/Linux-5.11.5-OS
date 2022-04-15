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
struct sigballoon_sub *sigb_head = NULL;
pid_t swapnames[MAX_SWAPFILES];
int CUSTOM_SWAPOUT = 0;

extern int vm_swappiness;
extern unsigned int nr_swapfiles;
extern int unsigned long shrink_all_memory(unsigned long nr_to_reclaim);
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
	struct sigballoon_sub *newsub = (struct sigballoon_sub*) malloc(sizeof(struct sigballoon_sub));
	vm_swappiness = 0;
	// check if process has already registered, should not be added to balloon_list again.
	
	if(!is_sigb_proc(current)) {
		newsub->task = current;
		newsub->next = sigb_head;
		sigb_head = newsub;
		newsub = NULL;
	}
	return 0;
}

SYSCALL_DEFINE0(unreg_sigballoon)
{
	// Set swappiness back to 60
	vm_swappiness = 60;
	// First lock all the user application pages in the memory to prevent swap.	
	struct sigballoon_sub *curr = sigb_head;
	struct sigballoon_sub *curr_prev = sigb_head;
	int found = 0;
	// check if process is registed to SIGBALLOON or not.
	if(!sigb_head) {
		printk("No Process registered for SIGBALLOON\n");
		return -1;
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
	return 0;
}

SYSCALL_DEFINE2(create_swapspace_pid, void __user *, start, size_t, size) 
{
	int ret;
	size_t reclaimed, i;
	unsigned int nr_pages = size >> 12;
	unsigned long vpn;
	/* 
	* Now add page_list to the swapfile
	* https://www.kernel.org/doc/gorman/html/understand/understand014.html
	* 11.8  Activating a Swap Area [above]
	* Maintain a single swap space filemm/swapfile.c (line 77), of the registered sigballoon process.
	*/
	swapnames[nr_swapfiles] = current->pid;
 	CUSTOM_SWAPOUT = 1;
	// printk("Reached before Madvise\n");
	for(i = 0 ; i < nr_pages; i++) {
		vpn = (((unsigned long)start) >> 12) + i;
		ret = do_madvise(current->mm, vpn << 12, (1 << 12), MADV_PAGEOUT);
		if(ret) {
			printk("Error %d on : %ld, %lu", ret, i, vpn);
			return ret;
		}
	}
	reclaimed = shrink_all_memory(nr_pages);
	// printk("Shrink All memory succeded! | Pages Freed: %luKB\n", reclaimed << 2);
	CUSTOM_SWAPOUT = 0;
	return 0;
}