#include <helpers/interfaces/variable_size_event.h>

SEC("fexit/security_bprm_creds_for_exec")
int BPF_PROG(security_bprm_creds_for_exec,
    struct linux_binprm *bprm, long ret) 
{
    struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SECURITY_BPRM_CREDS_FOR_EXEC_X);

    /*=============================== COLLECT PARAMETERS  ===========================*/

    auxmap__store_charbuf_param(auxmap, (unsigned long)bprm->filename, MAX_PATH, KERNEL);
    
    /*=============================== COLLECT PARAMETERS  ===========================*/

    auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

    return 0;
}