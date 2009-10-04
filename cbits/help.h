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

#endif /* __GCRYPT_HELP__ */
