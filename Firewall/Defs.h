#ifndef _DEFS_H_
#define _DEFS_H_

typedef enum { FALSE = 0, TRUE = 1 } Bool;

#define RULES_DEVICE_NAME "fw_rules"
#define LOG_DEVICE_NAME "fw_log"
#define CONNECTIONS_DEVICE_NAME "fw_conn_tab"
#define HOSTS_DEVICE_NAME "fw_hosts"
#define SYSFS_CLASS_NAME "fw"
#define RULES_TABLE_SYSFS_ATTR_NAME "rules_table"
#define RULES_SIZE_SYSFS_ATTR_NAME "rules_size"
#define RULES_ACTIVE_SYSFS_ATTR_NAME "rules_active"
#define LOG_SIZE_SYSFS_ATTR_NAME "log_size"
#define LOG_CLEAR_SYSFS_ATTR_NAME "log_clear"
#define HOSTS_SYSFS_ATTR_NAME "hosts_attr"

#define RULES_DELIMITER "\n"
#define HOSTS_DELIMITER_CHAR '\n'
#define HOSTS_DELIMITER_STR "\n"
#define HTTP_LINES_DELIMITER "\r\n"
#define HTTP_HOST_FIELD_MAX_LENGTH 100
#define HTTP_HOST_FIELD_NAME "Host:"
#define ACTION_ACCEPT 1
#define ACTION_DROP 0
#define PREFIX_SIZE_MIN 0
#define PREFIX_SIZE_MAX 32
#define UNSIGNED_BYTE_MIN 0
#define UNSIGNED_BYTE_MAX 255
#define ACTIVATE_CHAR '1'
#define DEACTIVATE_CHAR '0'

#define MAX_KERNEL_LOG_ROW_LENGTH 100
#define MAX_KERNEL_CONNECTION_STR_LENGTH 100

#define FTP_PORT 21
#define FTP_DATA_PORT 20
#define HTTP_PORT 80

#define UDP_HEADER_LENGTH 8

/* Defining a macro, similar to the macro __ATTR (which is used in the macro DEVICE_ATTR),
except that this macro doesn't stringify (adds " ") the attribute's name.
I'm defining this macro in order to be able to define the attribute's name as a constant. */
#define DEV_ATTR_DECLARATION(_name, _mode, _show, _store) {              \
         .attr = {.name = _name, .mode = _mode },						 \
         .show   = _show,                                                \
         .store  = _store,                                               \
 }

typedef enum
{
	SENT_SYN = 0,
	SENT_SYN_ACK,
	ESTABLISHED,
	SENT_FIN,
	FTP_SENT_PORT,
	FTP_SENT_PORT_SUCCESSFUL,

} ConnectionStateDescription;

#endif // _DEFS_H_
