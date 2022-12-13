#include <helpers/interfaces/variable_size_event.h>

SEC("fexit/security_socket_create")
int BPF_PROG(socket_create,
	     int family, int type, int protocol, int kern, long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SECURITY_SOCKET_CREATE_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* send header + 16 byte */
	auxmap__store_s64_param(auxmap, ret);

	auxmap__store_s64_param(auxmap, ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}
