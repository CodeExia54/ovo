#include <linux/kernel.h>
#include <linux/sched.h>

#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>

extern struct mm_struct *get_task_mm(struct task_struct *task);
extern void mmput(struct mm_struct *);

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {
    pgd_t *pgd;
    p4d_t *p4d;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;
	
    phys_addr_t page_addr;
    uintptr_t page_offset;
    
    pgd = pgd_offset(mm, va);
    if(pgd_none(*pgd) || pgd_bad(*pgd)) {
        return 0;
    }
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
    	return 0;
    }
	pud = pud_offset(p4d,va);
	if(pud_none(*pud) || pud_bad(*pud)) {
        return 0;
    }
	pmd = pmd_offset(pud,va);
	if(pmd_none(*pmd)) {
        return 0;
    }
	pte = pte_offset_kernel(pmd,va);
	if(pte_none(*pte)) {
        return 0;
    }
	if(!pte_present(*pte)) {
        return 0;
    }
	//PFN_PHYS(x)
	page_addr = ((phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT);
	//PFN_ALIGN(x)
	page_offset = (va & (PAGE_SIZE - 1)) & PAGE_MASK;
	
	return (page_addr + page_offset) | (va & 0xFFF);
}
#else
phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {

    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;
	
    phys_addr_t page_addr;
    uintptr_t page_offset;
    
    pgd = pgd_offset(mm, va);
    if(pgd_none(*pgd) || pgd_bad(*pgd)) {
        return 0;
    }
	pud = pud_offset(pgd,va);
	if(pud_none(*pud) || pud_bad(*pud)) {
        return 0;
    }
	pmd = pmd_offset(pud,va);
	if(pmd_none(*pmd)) {
        return 0;
    }
	pte = pte_offset_kernel(pmd,va);
	if(pte_none(*pte)) {
        return 0;
    }
	if(!pte_present(*pte)) {
        return 0;
    }
	//PFN_PHYS(x)
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	//PFN_ALIGN(x)
	page_offset = va & (PAGE_SIZE-1);
	
	return (page_addr + page_offset) | (va & 0xFFF);
}
#endif

bool read_physical_address(phys_addr_t pa, void* buffer, size_t size) { 
#if(LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0))
    if (!pfn_valid(__phys_to_pfn(pa))) {
        pr_err("read_physical_address pfn_valid failed.\n");
        return false;
    }
#endif
    return !copy_to_user(buffer, __va(pa), size);
}

bool write_physical_address(phys_addr_t pa, void* buffer, size_t size) {
#if(LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0))
    if (!pfn_valid(__phys_to_pfn(pa))) {
        pr_err("write_physical_address pfn_valid failed.\n");
        return false;
    }
#endif
    return !copy_from_user(__va(pa), buffer, size);
}

bool read_process_memory(
    pid_t pid, 
    uintptr_t addr, 
    void* buffer, 
    size_t size,
    bool isWrite) {
    
    struct task_struct* task;
    struct mm_struct* mm;
    struct pid* pid_struct;
    // struct vm_area_struct* vma;
    phys_addr_t pa;

    // pr_info("read_process_memory - pid: %d, addr: %lx, size: %zu\n", pid, addr, size);
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        pr_err("pvm: a-read_process_memory pid_struct failed.\n");
        return false;
    }
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task) {
        pr_err("pvm: a-read_process_memory task failed.\n");
        return false;
    }
	mm = get_task_mm(task);
    if (!mm) {
        pr_err("pvm: a-read_process_memory mm failed.\n");
        return false;
    }
    /*
    vma = find_vma(mm, addr);
    if(isWrite) {
        if(!vma || (vma->vm_flags & VM_WRITE) == 0 || (addr + size) > vma->vm_end){
            mmput(mm);
            pr_err("pvm: a-read_process_memory vma failed (write).\n");
            return false;
	}
    } else {
        if(!vma || (vma->vm_flags & VM_READ) == 0 || (addr + size) > vma->vm_end){
            mmput(mm);
            pr_err("pvm: a-read_process_memory vma failed.\n");
            return false;
        }
    }
    */
    mmput(mm);
    pa = translate_linear_address(mm, addr);
    if (!pa) {
        pr_err("read_process_memory pa failed.\n");
        return false;
    }
    return read_physical_address(pa, buffer, size);
}

bool write_process_memory(
    pid_t pid, 
    uintptr_t addr, 
    void* buffer, 
    size_t size) {
    
    struct task_struct* task;
    struct mm_struct* mm;
    struct pid* pid_struct;
    struct vm_area_struct* vma;
    phys_addr_t pa;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return false;
    }
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        return false;
    }
    mm = get_task_mm(task);
    if (!mm) {
        return false;
    }
    vma = find_vma(mm, addr);
    if(!vma || (vma->vm_flags & VM_READ) == 0 || (addr + size) > vma->vm_end){
        mmput(mm);
        return false;
    }
    mmput(mm);
    pa = translate_linear_address(mm, addr);
    if (!pa) {
        return false;
    }
    return write_physical_address(pa,buffer,size);
}
