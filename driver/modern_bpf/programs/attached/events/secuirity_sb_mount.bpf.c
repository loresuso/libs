#include <helpers/interfaces/variable_size_event.h>

SEC("fexit/security_sb_mount")
int BPF_PROG(sb_mount,
	     const char *dev_name, const struct path *path, const char *type, long unsigned int flags, void *data, long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SECURITY_SB_MOUNT_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* send header + 16 byte */
	auxmap__store_s64_param(auxmap, ret);

	auxmap__store_s64_param(auxmap, ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}
