#pragma once

/* | name | path | */
#define TP_FIELDS                                                       \
	X(SYS_ENTER, "sys_enter")                                       \
	X(SYS_EXIT, "sys_exit")                                         \
	X(SCHED_PROC_EXIT, "sched_process_exit")                        \
	X(SCHED_SWITCH, "sched_switch")                                 \
	X(PAGE_FAULT_USER, "page_fault_user")                           \
	X(PAGE_FAULT_KERN, "page_fault_kernel")                         \
	X(SIGNAL_DELIVER, "signal_deliver")                             \
	X(SCHED_PROC_FORK, "sched_process_fork")                        \
	X(SCHED_PROC_EXEC, "sched_process_exec")                        \
	X(SECURITY_FILE_OPEN, "security_file_open")                     \
	X(SECURITY_BPRM_CREDS_FOR_EXEC, "security_bprm_creds_for_exec") \
	X(SECURITY_INODE_UNLINK, "security_inode_unlink")               \
	X(SECURITY_SOCKET_ACCEPT, "security_socket_accept")             \
	X(SECURITY_SOCKET_BIND, "security_socket_bind")                 \
	X(SECURITY_SOCKET_CONNECT, "security_socket_connect")           \
	X(SECURITY_SOCKET_CREATE, "security_socket_create")             \
	X(SECURITY_SOCKET_LISTEN, "security_socket_listen")             \
	X(SECURITY_SB_MOUNT, "security_sb_mount")

typedef enum
{
#define X(name, path) name,
	TP_FIELDS
#undef X
		TP_VAL_MAX,
} tp_values;

extern const char *tp_names[];
extern tp_values tp_from_name(const char *tp_path);
