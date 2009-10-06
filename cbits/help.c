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

gcry_error_t wrap_gcry_cipher_setiv(gcry_cipher_hd_t h, char * k, size_t l)
{
    return gcry_cipher_setiv(h,k,l);
}

gcry_error_t wrap_gcry_cipher_setkey(gcry_cipher_hd_t h, char * k, size_t l)
{
    return gcry_cipher_setkey(h,k,l);
}

gcry_error_t wrap_gcry_cipher_sync(gcry_cipher_hd_t h)
{
    return gcry_cipher_sync(h);
}

/* gcry_control wrappers */
gcry_error_t wrap_gcry_control_0(enum gcry_ctl_cmds cmd)
{
    return gcry_control(cmd);
}

gcry_error_t wrap_gcry_control_constcharptr(enum gcry_ctl_cmds cmd, const char * ccp)
{
    return gcry_control(cmd,ccp);
}

gcry_error_t wrap_gcry_control_int(enum gcry_ctl_cmds cmd, int i)
{
    return gcry_control(cmd,i);
}

gcry_error_t wrap_gcry_control_uint(enum gcry_ctl_cmds cmd, unsigned int i)
{
    return gcry_control(cmd,i);
}

gcry_error_t wrap_gcry_control_voidptr(enum gcry_ctl_cmds cmd, void * p)
{
    return gcry_control(cmd,p);
}

