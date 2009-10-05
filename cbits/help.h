#ifndef __GCRYPT_HELP__
#define __GCRYPT_HELP__ __GCRYPT_HELP__

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

#endif /* __GCRYPT_HELP__ */
