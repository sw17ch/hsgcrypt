#ifndef __GCRYPT_HELP__
#define __GCRYPT_HELP__ __GCRYPT_HELP__

#include <stdio.h>
#include <gcrypt.h>
#include <gcrypt-module.h>


void gcry_ac_io_init_readable_string(gcry_ac_io_t *ac_io,
    unsigned char * str, unsigned long size);

void gcry_ac_io_init_writable_string(gcry_ac_io_t *ac_io,
    unsigned char ** str, unsigned long * size);

void gcry_ac_io_init_readable_callback(gcry_ac_io_t *ac_io,
    gcry_ac_data_read_cb_t cb, void * arg);

void gcry_ac_io_init_writable_callback(gcry_ac_io_t *ac_io,
    gcry_ac_data_write_cb_t cb, void * arg);

gcry_error_t wrap_gcry_cipher_reset(gcry_cipher_hd_t h);
gcry_error_t wrap_gcry_cipher_setctr(gcry_cipher_hd_t h, char * k, size_t l);
gcry_error_t wrap_gcry_cipher_setiv(gcry_cipher_hd_t h, char * k, size_t l);
gcry_error_t wrap_gcry_cipher_setkey(gcry_cipher_hd_t h, char * k, size_t l);
gcry_error_t wrap_gcry_cipher_sync(gcry_cipher_hd_t h);

/* The following area sets up wrappers for gcry_control. It has a long
 * list of variable argument formats which we need to break out
 * individually. */

/* gcry_control, 0 arguments. */
gcry_error_t wrap_gcry_control_0(enum gcry_ctl_cmds cmd);

/* gcry_control, 'const char *' */
gcry_error_t wrap_gcry_control_constcharptr(enum gcry_ctl_cmds cmd, const char * ccp);

/* gcry_control, 'int' */
gcry_error_t wrap_gcry_control_int(enum gcry_ctl_cmds cmd, int i);

/* gcry_control, 'unsigned int' */
gcry_error_t wrap_gcry_control_uint(enum gcry_ctl_cmds cmd, unsigned int i);

/* gcry_control, 'void *' */
gcry_error_t wrap_gcry_control_voidptr(enum gcry_ctl_cmds cmd, void * p);

/* gcry_control, 'FILE *' */
gcry_error_t wrap_gcry_control_fileptr(enum gcry_ctl_cmds cmd, FILE * f); 

/* End of gcry_control wrappers */

void wrap_gcry_md_final(gcry_md_hd_t h);
gcry_error_t wrap_gcry_md_get_asnoid(int algo, void * buffer, size_t * length);
void wrap_gcry_md_putc(gcry_md_hd_t h, int c);
void wrap_gcry_md_start_debug(gcry_md_hd_t h, const char * suffix);
void wrap_gcry_md_stop_debug(gcry_md_hd_t h, const char * suffix);
gcry_error_t wrap_gcry_md_test_algo(int algo);
int wrap_gcry_pk_test_algo(int algo);

#endif /* __GCRYPT_HELP__ */

