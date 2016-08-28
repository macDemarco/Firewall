#ifndef _WordpressCveFix_H_
#define _WordpressCveFix_H_

#include "KernelDefs.h"

/* Constants */
#define WORDPRESS_HTTP_POST_PREFIX "POST /wp-admin/admin-ajax.php?action=bwg_UploadHandler"
#define HTTP_CONTENT_TYPE_STR "Content-Type: multipart/form-data; boundary="
#define ZIP_FILE_BEGINNING "PK\x03\x04"
#define EMPTY_LINE "\x0d\x0a\x0d\x0a"

/* Exported functions */


Bool retrieveFileBoundary(packet_info_t * packetInfo, unsigned char * boundary, unsigned int * messageIndex);
Bool doesContainZipFile(packet_info_t * packetInfo, unsigned char * boundary, unsigned int messageIndex);
Bool isHttpPostOver(packet_info_t * packetInfo, unsigned char * boundary);

/* Checks if it starts with 'post /wp-admin/...' */
Bool isWordpressHttpPostPacket(packet_info_t * packetInfo);

#endif // _WordpressCveFix_H_
