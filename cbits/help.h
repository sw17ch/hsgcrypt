#ifndef __GCRYPT_HELP__
#define __GCRYPT_HELP__ __GCRYPT_HELP__

#include <gcrypt.h>


typedef gpg_error_t (*gcry_ac_data_read_cb_4hs_t) (void *opaque,
					       unsigned char *buffer,
					       unsigned long *buffer_n);

typedef gpg_error_t (*gcry_ac_data_write_cb_4hs_t) (void *opaque,
						unsigned char *buffer,
						unsigned long buffer_n);

void gcry_ac_io_init_readable_string(gcry_ac_io_t *ac_io,
    unsigned char * str, unsigned long size);

void gcry_ac_io_init_writable_string(gcry_ac_io_t *ac_io,
    unsigned char ** str, unsigned long * size);

void gcry_ac_io_init_readable_callback(gcry_ac_io_t *ac_io,
    gcry_ac_data_read_cb_4hs_t cb, void * arg);

void gcry_ac_io_init_writable_callback(gcry_ac_io_t *ac_io,
    gcry_ac_data_write_cb_4hs_t cb, void * arg);
#endif /* __GCRYPT_HELP__ */
