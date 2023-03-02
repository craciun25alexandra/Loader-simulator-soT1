/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>

#include "exec_parser.h"
#define PAGE_SIZE getpagesize()
static so_exec_t *exec;
static int fd;


static void segv_handler(int signum, siginfo_t *info, void *context)
{
	/* TODO - actual loader implementation */
	
	struct so_seg segment;
	//caut in ce segment face parte
	for(int i = 0; i< exec->segments_no; i++){
		segment = exec->segments[i];
		if(segment.vaddr <= (int)info->si_addr &&
				(int)segment.vaddr + segment.mem_size >= (int)info->si_addr){
			// in ce pagina face parte
			int nr_page = ((int)info->si_addr - (int)segment.vaddr) / PAGE_SIZE;
			// daca nu s a mapat nicio pagina in segmentul dat se aloca un vector
			//pentru nr de pagini si se initializeaza cu 0
			if (!exec->segments[i].data){
				if(segment.mem_size % PAGE_SIZE == 0)
				exec->segments[i].data = calloc(segment.mem_size / PAGE_SIZE, sizeof(char));
				else
				exec->segments[i].data = calloc(segment.mem_size / PAGE_SIZE + 1, sizeof(char));}
			//daca a mai fost mapata pagina intra in handlerul default
			if (*(char *)(exec->segments[i].data + nr_page) == '1')
				{
					signal(SIGSEGV, SIG_DFL);
					return;
				}
			// se mapeaza pagina
			mmap((void *)(segment.vaddr + nr_page * PAGE_SIZE),
				 PAGE_SIZE, PROT_WRITE , MAP_PRIVATE | MAP_FIXED | MAP_ANON , -1, 0);
			// se marcheaza mapata
			(*(char *)(exec->segments[i].data + nr_page))= '1';
			//pagina din afara file ului, pun 0 pe toata pagina
			if(segment.file_size < nr_page * PAGE_SIZE)
				memset((void *)segment.vaddr + nr_page * PAGE_SIZE, 0 , PAGE_SIZE);
			//file ul este pe o parte din pagina, restul pun 0
			else if(segment.file_size < (nr_page + 1) * PAGE_SIZE){
				lseek(fd, segment.offset + nr_page * PAGE_SIZE, SEEK_SET);
				int diff = segment.file_size - nr_page * PAGE_SIZE;
				read(fd, (void *)(segment.vaddr + nr_page * PAGE_SIZE), diff);
				memset((void *)(segment.vaddr + nr_page * PAGE_SIZE + diff), 0 , PAGE_SIZE - diff);
			}
			//file ul pe toata pagina
			else {
			lseek(fd, segment.offset + nr_page * PAGE_SIZE, SEEK_SET);
			read(fd, (void*)(segment.vaddr + nr_page * PAGE_SIZE), PAGE_SIZE);
			}
		//permisiuni
		int prot = 0;
			if (segment.perm & PERM_R)
				prot |= PROT_READ;
			if (segment.perm & PERM_W)
				prot |= PROT_WRITE;
			if (segment.perm & PERM_X)
				prot |= PROT_EXEC;
			mprotect((void*)(segment.vaddr + nr_page * PAGE_SIZE), PAGE_SIZE, prot);
			return;
			}

		}
	signal(SIGSEGV, SIG_DFL);
}

int so_init_loader(void)
{
	int rc;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	rc = sigaction(SIGSEGV, &sa, NULL);
	if (rc < 0) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{
	fd = open(path, O_RDONLY);
	exec = so_parse_exec(path);
	if (!exec)
		return -1;
	so_start_exec(exec, argv);

	return -1;
}
