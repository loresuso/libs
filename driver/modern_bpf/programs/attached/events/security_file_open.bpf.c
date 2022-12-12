#include <helpers/interfaces/variable_size_event.h>

char filename[MAX_PATH] = {};

SEC("fexit/security_file_open")
int BPF_PROG(security_file_open,
    struct file *file, long ret) 
{
    bpf_printk("start");
    struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SECURITY_OPEN_X);

    /*=============================== COLLECT PARAMETERS  ===========================*/

    bpf_d_path(&file->f_path, filename, MAX_PATH);
    auxmap__store_charbuf_param(auxmap, (unsigned long)&filename, MAX_PATH, KERNEL);

    auxmap__store_u64_param(auxmap, file->f_inode->i_sb->s_magic);
    
    /*=============================== COLLECT PARAMETERS  ===========================*/

    auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);
    bpf_printk("end");

    return 0;
}