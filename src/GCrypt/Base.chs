{-# LANGUAGE ForeignFunctionInterface,
             GeneralizedNewtypeDeriving #-}
{-# OPTIONS -fno-warn-unused-binds #-}

module GCrypt.Base where

import Foreign.C.Types
import Foreign.C.String
import Foreign.Ptr

import Data.Word

import GPG.Error

#include "help.h"

{- Helper functions to help marshal. -}
fromEnumInt :: (Num b, Enum a) => a -> b
fromEnumInt = fromIntegral . fromEnum

{#context lib = "gcrypt" prefix = "gcry"#}

{-
 - Notes:
 -
 - AC (i think) stands for Assymetric Cypher or Crytpography.
 - 
 - We don't bind the gcry_ac_io_init_va because it is
 - redundant over gcry_ac_io_init.
 -}

{- Pointer types used by libgcrypt -}
{#pointer gcry_ac_handle_t as ACHandle newtype#}
{#pointer gcry_ac_data_t as ACData newtype#}
{#pointer *gcry_ac_io_t as ACIO newtype#}
{#pointer gcry_ac_key_t as ACKey newtype#}
{#pointer gcry_mpi_t as ACMPI newtype#}
{#pointer gcry_sexp_t as SExp newtype#}
{#pointer gcry_ac_key_pair_t as ACKeyPair newtype#}
{#pointer gcry_cipher_hd_t as CipherHd newtype#}
{#pointer *gcry_cipher_spec_t as CipherSpec newtype#}
{#pointer gcry_module_t as GCryModule newtype#}

-- Sometimes we need pointers-to-pointers
newtype ACHandlePtr = ACHandlePtr {unACHandlePtr :: Ptr ACHandle}
newtype ACDataPtr = ACDataPtr {unACDataPtr :: Ptr ACData}
newtype ACIOPtr = ACIOPtr {unACIOPtr :: Ptr ACIO}
newtype ACMPIPtr = ACMPIPtr {unACMPIPtr :: Ptr ACMPI}
newtype ACMPIPtrPtr = ACMPIPtrPtr {unACMPIPtrPtr :: Ptr (Ptr ACMPI)}
newtype ACKeyPtr = ACKeyPtr {unACKeyPtr :: Ptr ACKey}
newtype ACKeyPairPtr = ACKeyPairPtr {unACKeyPairPtr :: Ptr ACKeyPair}
newtype SExpPtr = SExpPtr {unSExpPtr :: Ptr SExp}
newtype CipherHdPtr = CipherHdPtr { unCipherHdPtr :: Ptr CipherHd }
newtype GCryModulePtr = GCryModulePtr { unGCryModulePtr :: Ptr GCryModule }

-- These will be more concrete later
type GCry_Options = Ptr ()
type Idents = Ptr CString
type Names = Ptr CString

{- Enumerations used by libgcrypt -}
{#enum gcry_ac_em_t as GCry_EncMethod {} deriving (Eq)#}
{#enum gcry_ac_scheme_t as GCry_Scheme {} deriving (Eq)#}
{#enum gcry_ac_id_t as GCry_AC_ID {} deriving (Eq)#}
{#enum gcry_ac_io_mode_t as GCry_AC_IO_Mode {} deriving (Eq)#}
{#enum gcry_ac_io_type_t as GCry_AC_IO_Type {} deriving (Eq)#}
{#enum gcry_ac_key_type_t as GCry_AC_Key_Type {} deriving (Eq)#}
{#enum gcry_ctl_cmds as GCry_Ctl_Cmd {} deriving (Eq)#}
{#enum gcry_cipher_algos as GCry_Cipher_Algo {} deriving (Eq)#}

type GCry_Error = GPG_Error

{- Aliased types for libgcrypt -}
newtype ACFlags   = ACFlags Word32   deriving (Integral,Real,Enum,Num,Ord,Eq,Show)
newtype DataIndex = DataIndex Word32 deriving (Integral,Real,Enum,Num,Ord,Eq,Show)

{-
 - Function definitions. Best reference is the libgcrypt docs.
 -}

{#fun gcry_ac_close {
        id `ACHandle'
    } -> `()' #}

{#fun gcry_ac_data_clear {
        id `ACData'
    } -> `()' #}

{#fun gcry_ac_data_copy {
        unACDataPtr `ACDataPtr',
        id `ACData'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_decode {
        fromEnumInt `GCry_EncMethod',
        fromIntegral `ACFlags',
        id `GCry_Options',
        id `ACIO',
        id `ACIO'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_decrypt {
        id `ACHandle',
        fromIntegral `ACFlags',
        id `ACKey',
        unACMPIPtr `ACMPIPtr',
        id `ACData'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_decrypt_scheme {
        id `ACHandle',
        fromEnumInt `GCry_Scheme',
        fromIntegral `ACFlags',
        id `GCry_Options',
        id `ACKey',
        id `ACIO',
        id `ACIO'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_destroy {
        id `ACData'
    } -> `()'#}

{#fun gcry_ac_data_encode {
        fromEnumInt `GCry_EncMethod',
        fromIntegral `ACFlags',
        id `GCry_Options',
        id `ACIO',
        id `ACIO'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_encrypt {
        id `ACHandle',
        fromIntegral `ACFlags',
        id `ACKey',
        id `ACMPI',
        unACDataPtr `ACDataPtr'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_encrypt_scheme {
        id `ACHandle',
        fromEnumInt `GCry_Scheme',
        fromIntegral `ACFlags',
        id `GCry_Options',
        id `ACKey',
        id `ACIO',
        id `ACIO'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_from_sexp {
        unACDataPtr `ACDataPtr',
        id `SExp',
        id `Idents'
    } -> `GCry_Error' fromIntegral#}
     
{#fun gcry_ac_data_get_index {
        id `ACData',
        fromIntegral `ACFlags',
        fromIntegral `DataIndex',
        id `Names',
        unACMPIPtr `ACMPIPtr'
    } -> `GCry_Error' fromIntegral#}
     
{#fun gcry_ac_data_get_name {
        id `ACData',
        fromIntegral `ACFlags',
        id `CString',
        unACMPIPtr `ACMPIPtr'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_length {
        id `ACData'
    } -> `Int' fromIntegral#}

{#fun gcry_ac_data_new {
        unACDataPtr `ACDataPtr'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_set {
        id `ACData',
        fromIntegral `ACFlags',
        id `CString',
        id `ACMPI'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_sign {
        id `ACHandle',
        id `ACKey',
        id `ACMPI',
        unACDataPtr `ACDataPtr'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_sign_scheme {
        id `ACHandle',
        fromEnumInt `GCry_Scheme',
        fromIntegral `ACFlags',
        id `GCry_Options',
        id `ACKey',
        id `ACIO',
        id `ACIO'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_to_sexp {
        id `ACData',
        unSExpPtr `SExpPtr',
        id `Idents'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_verify {
        id `ACHandle',
        id `ACKey',
        id `ACMPI',
        id `ACData'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_verify_scheme {
        id `ACHandle',
        fromEnumInt `GCry_Scheme',
        fromIntegral `ACFlags',
        id `GCry_Options',
        id `ACKey',
        id `ACIO',
        id `ACIO'
    } -> `GCry_Error' fromIntegral#}

{- DEPRECIATED -}
{#fun gcry_ac_id_to_name as gcry_ac_id_to_name__DEPRECIATED {
        fromEnumInt `GCry_AC_ID',
        id `Ptr CString'
    } -> `GCry_Error' fromIntegral#}

{- DEPRECIATED -}
-- Note: the CInt is actually a GCry_AC_ID
{#fun gcry_ac_name_to_id as gcry_ac_name_to_id__DEPRECIATED {
        id `CString',
        id `Ptr CInt'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_io_init_readable_string {
        id `ACIO',
        id `Ptr CUChar',
        id `CULong'
    } -> `()'#}

{#fun gcry_ac_io_init_writable_string {
        id `ACIO',
        id `Ptr (Ptr CUChar)',
        id `Ptr CULong'
    } -> `()'#}

type ReadableCallback = Ptr () -> Ptr CUChar -> Ptr CSize -> IO CUInt
{#fun gcry_ac_io_init_readable_callback {
        id `ACIO',
        castFunPtr `FunPtr ReadableCallback',
        id `Ptr ()'
    } -> `()'#}

type WritableCallback = Ptr () -> Ptr CUChar -> CSize -> IO CUInt
{#fun gcry_ac_io_init_writable_callback {
        id `ACIO',
        castFunPtr `FunPtr WritableCallback',
        id `Ptr ()'
    } -> `()'#}

{#fun gcry_ac_key_data_get {
        id `ACKey'
    } -> `ACData' id#}

{#fun gcry_ac_key_destroy {
        id `ACKey'        
    } -> `()'#}

{#fun gcry_ac_key_get_grip {
        id `ACHandle',
        id `ACKey',
        id `Ptr CUChar'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_key_get_nbits {
        id `ACHandle',
        id `ACKey',
        id `Ptr CUInt'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_key_init {
        unACKeyPtr `ACKeyPtr',
        id `ACHandle',
        fromEnumInt `GCry_AC_Key_Type',
        id `ACData'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_key_pair_destroy {
        id `ACKeyPair'
    } -> `()'#}

{#fun gcry_ac_key_pair_extract {
        id `ACKeyPair',
        fromEnumInt `GCry_AC_Key_Type'
    } -> `()'#}

-- NOTE: Last parameter is always nullPtr.
-- Currently unimplemented by libgcrypt.
{#fun gcry_ac_key_pair_generate {
        id `ACHandle',
        id `CUInt',
        id `Ptr ()',
        unACKeyPairPtr `ACKeyPairPtr',
        unACMPIPtrPtr `ACMPIPtrPtr'
    } -> `()'#}

{#fun gcry_ac_key_test {
        id `ACHandle',
        id `ACKey'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_open {
        unACHandlePtr `ACHandlePtr',
        fromEnumInt `GCry_AC_ID',
        fromIntegral `ACFlags'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_calloc {
        fromIntegral `CSize',
        fromIntegral `CSize'
    } -> `Ptr ()' id#}

{#fun gcry_calloc_secure {
        fromIntegral `CSize',
        fromIntegral `CSize'
    } -> `Ptr ()' id#}

{#fun gcry_check_version {
        id `CString'
    } -> `CString' id#}

{#fun gcry_cipher_algo_info {
        fromEnumInt `GCry_Cipher_Algo',
        fromEnumInt `GCry_Ctl_Cmd',
        id `Ptr ()',
        castPtr `Ptr CSize'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_cipher_algo_name {
        fromEnumInt `GCry_Cipher_Algo'
    } -> `CString' id#}

{#fun gcry_cipher_close {
        id `CipherHd'
    } -> `()'#}

{#fun gcry_cipher_ctl {
        id `CipherHd',
        fromEnumInt `GCry_Ctl_Cmd',
        id `Ptr ()',
        fromIntegral `CSize'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_cipher_decrypt {
        id `CipherHd',
        id `Ptr ()',
        fromIntegral `CSize',
        id `Ptr ()',
        fromIntegral `CSize'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_cipher_encrypt {
        id `CipherHd',
        id `Ptr ()',
        fromIntegral `CSize',
        id `Ptr ()',
        fromIntegral `CSize'
    } -> `GCry_Error' fromIntegral#}

{-
 - gcry_error_t gcry_cipher_info (gcry_cipher_hd_t h, int what, void *buffer,
 -                               size_t *nbytes);
 -
 - Return information about the cipher handle H.  CMD is the kind of
 - information requested.  BUFFER and NBYTES are reserved for now.
 - 
 - There are no values for CMD yet defined.  
 - 
 - The fucntion always returns GPG_ERR_INV_OP.
 -}
{#fun gcry_cipher_info {
        id `CipherHd',
        id `CInt',
        id `Ptr ()',
        castPtr `Ptr CSize'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_cipher_list {
        id `Ptr CInt',
        id `Ptr CInt'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_cipher_map_name {
        id `CString'
    } -> `CInt' id#}

{#fun gcry_cipher_mode_from_oid {
        id `CString'
    } -> `CInt' id#}

{#fun gcry_cipher_open {
        unCipherHdPtr `CipherHdPtr',
        id `CInt',
        id `CInt',
        fromIntegral `ACFlags'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_cipher_register {
        id `CipherSpec',
        id `Ptr CInt',
        unGCryModulePtr `GCryModulePtr'
    } -> `GCry_Error' fromIntegral#}

{#fun wrap_gcry_cipher_reset as gcry_cipher_reset {
        id `CipherHd'
    } -> `GCry_Error' fromIntegral#}

{#fun wrap_gcry_cipher_setctr as gcry_cipher_setctr {
        id `CipherHd',
        id `CString',
        fromIntegral `CSize'
    } -> `GCry_Error' fromIntegral#}

{#fun wrap_gcry_cipher_setiv as gcry_cipher_setiv {
        id `CipherHd',
        id `CString',
        fromIntegral `CSize'
    } -> `GCry_Error' fromIntegral#}

{#fun wrap_gcry_cipher_setkey as gcry_cipher_setkey {
        id `CipherHd',
        id `CString',
        fromIntegral `CSize'
    } -> `GCry_Error' fromIntegral#}

{#fun wrap_gcry_cipher_sync as gcry_cipher_sync {
        id `CipherHd'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_cipher_unregister {
        id `GCryModule'
    } -> `()'#}

{- gcry_control function bindings. there are a lot of these -}

{- 0 argument commands:
    GCRYCTL_ENABLE_M_GUARD
    GCRYCTL_ENABLE_QUICK_RANDOM
    GCRYCTL_DUMP_RANDOM_STATS
    GCRYCTL_DUMP_MEMORY_STATS
    GCRYCTL_DUMP_MEMORY_STATS
    GCRYCTL_DROP_PRIVS
    GCRYCTL_DISABLE_SECMEM
    GCRYCTL_INIT_SECMEM
    GCRYCTL_TERM_SECMEM
    GCRYCTL_DISABLE_SECMEM_WARN
    GCRYCTL_SUSPEND_SECMEM_WARN
    GCRYCTL_RESUME_SECMEM_WARN
    GCRYCTL_USE_SECURE_RNDPOOL
    GCRYCTL_UPDATE_RANDOM_SEED_FILE
    GCRYCTL_DISABLE_INTERNAL_LOCKING
    GCRYCTL_ANY_INITIALIZATION_P
    GCRYCTL_INITIALIZATION_FINISHED
    GCRYCTL_INITIALIZATION_FINISHED_P
    GCRYCTL_FAST_POLL
    GCRYCTL_OPERATIONAL_P
    GCRYCTL_FIPS_MODE_P
    GCRYCTL_FORCE_FIPS_MODE
    GCRYCTL_SELFTEST
-}

{#fun wrap_gcry_control_0 {
        fromEnumInt `GCry_Ctl_Cmd'  
    } -> `GCry_Error' fromIntegral#}

{- 'const char *' commands:
    GCRYCTL_SET_RANDOM_SEED_FILE
    GCRYCTL_SET_RNDEGD_SOCKET
-}
{#fun wrap_gcry_control_constcharptr {
        fromEnumInt `GCry_Ctl_Cmd',
        id `CString'
    } -> `GCry_Error' fromIntegral#}

{- 'int' commands:
    GCRYCTL_SET_VERBOSITY
-}
{#fun wrap_gcry_control_int {
        fromEnumInt `GCry_Ctl_Cmd',
        id `CInt'
    } -> `GCry_Error' fromIntegral#}

{- 'unsigned int' commands:
    GCRYCTL_SET_DEBUG_FLAGS
    GCRYCTL_CLEAR_DEBUG_FLAGS
-}
{#fun wrap_gcry_control_uint {
        fromEnumInt `GCry_Ctl_Cmd',
        id `CUInt'
    } -> `GCry_Error' fromIntegral#}

{- 'struct auth_ops *' commands:
    GCRYCTL_SET_THREAD_CBS
-}
{#fun wrap_gcry_control_voidptr {
        fromEnumInt `GCry_Ctl_Cmd',
        id `Ptr ()'
    } -> `GCry_Error' fromIntegral#}

{- 'FILE *' commands:
   GCRYCTL_PRINT_CONFIG
-}
{#fun wrap_gcry_control_fileptr {
        fromEnumInt `GCry_Ctl_Cmd',
        castPtr `Ptr CFile'
    } -> `GCry_Error' fromIntegral#}
