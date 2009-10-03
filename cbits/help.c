#include "help.h"

void gcry_ac_io_init_readable_string(gcry_ac_io_t *ac_io,
    unsigned char * str, unsigned long size)
{
    gcry_ac_io_init(ac_io, GCRY_AC_IO_READABLE, GCRY_AC_IO_STRING, str, size);
}

void gcry_ac_io_init_writable_string(gcry_ac_io_t *ac_io,
    unsigned char ** str, unsigned long * size)
{
    gcry_ac_io_init(ac_io, GCRY_AC_IO_WRITABLE, GCRY_AC_IO_STRING, str, size);
}

void gcry_ac_io_init_readable_callback(gcry_ac_io_t *ac_io,
    gcry_ac_data_read_cb_t cb, void * arg)
{
    gcry_ac_io_init(ac_io, GCRY_AC_IO_READABLE, GCRY_AC_IO_CALLBACK, cb, arg);
}

void gcry_ac_io_init_writable_callback(gcry_ac_io_t *ac_io,
    gcry_ac_data_write_cb_t cb, void * arg)
{
    gcry_ac_io_init(ac_io, GCRY_AC_IO_WRITABLE, GCRY_AC_IO_CALLBACK, cb, arg);
}

gcry_error_t wrap_gcry_cipher_reset(gcry_cipher_hd_t h)
{
    return gcry_cipher_reset(h);
}

gcry_error_t wrap_gcry_cipher_setctr(gcry_cipher_hd_t h, char * k, size_t l)
{
    return gcry_cipher_setctr(h,k,l);
}
