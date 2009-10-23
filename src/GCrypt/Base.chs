{-# LANGUAGE ForeignFunctionInterface,
             GeneralizedNewtypeDeriving #-}
{-# OPTIONS -fno-warn-unused-binds #-}

module GCrypt.Base where

import Foreign.Storable
import Foreign.C.Types
import Foreign.C.String
import Foreign.Ptr
import Foreign.Marshal.Alloc

import Data.Word
import Data.Int

import GPG.Error

#include "help.h"

{- Helper functions to help marshal. -}
fromEnumInt :: (Num b, Enum a) => a -> b
fromEnumInt = fromIntegral . fromEnum

toIntEnum :: (Integral a, Enum b) => a -> b
toIntEnum = toEnum . fromIntegral

{#context lib = "gcrypt" prefix = "gcry"#}

-- This comes into play more than it should
{#pointer *size_t as CSizePtr newtype#}

{-
 - Notes:
 -
 - AC (i think) stands for Assymetric Cypher or Crytpography.
 - 
 - We don't bind the gcry_ac_io_init_va because it is
 - redundant over gcry_ac_io_init.
 -}

{- Pointer types used by libgcrypt -}
{#pointer gcry_ac_handle_t as ACHandle newtype#} deriving (Show,Storable)
{#pointer gcry_ac_data_t as ACData newtype#} deriving (Show,Storable)
{#pointer *gcry_ac_io_t as ACIO newtype#} deriving (Show,Storable)
{#pointer gcry_ac_key_t as ACKey newtype#} deriving (Show,Storable)
{#pointer gcry_mpi_t as MPI newtype#} deriving (Show,Storable)
{#pointer gcry_sexp_t as SExp newtype#} deriving (Show,Storable)
{#pointer gcry_ac_key_pair_t as ACKeyPair newtype#} deriving (Show,Storable)
{#pointer gcry_cipher_hd_t as CipherHd newtype#} deriving (Show,Storable)
{#pointer *gcry_cipher_spec_t as CipherSpec newtype#} deriving (Show,Storable)
{#pointer gcry_module_t as GCryModule newtype#} deriving (Show,Storable)
{#pointer gcry_md_hd_t as GCryMdHd newtype#} deriving (Show,Storable)
{#pointer *gcry_md_spec_t as GCryMdSpec newtype#} deriving (Show,Storable)
{#pointer *gcry_pk_spec_t as GCryPkSpec newtype#} deriving (Show,Storable)
{#pointer *gcry_error_t as GCry_Error_Ptr newtype#} deriving (Show,Storable)

-- Sometimes we need pointers-to-pointers
newtype ACHandlePtr = ACHandlePtr {unACHandlePtr :: Ptr ACHandle}
newtype ACDataPtr = ACDataPtr {unACDataPtr :: Ptr ACData}
newtype ACIOPtr = ACIOPtr {unACIOPtr :: Ptr ACIO}
newtype MPIPtr = MPIPtr {unMPIPtr :: Ptr MPI}
newtype MPIPtrPtr = MPIPtrPtr {unMPIPtrPtr :: Ptr (Ptr MPI)}
newtype ACKeyPtr = ACKeyPtr {unACKeyPtr :: Ptr ACKey}
newtype ACKeyPairPtr = ACKeyPairPtr {unACKeyPairPtr :: Ptr ACKeyPair}
newtype SExpPtr = SExpPtr {unSExpPtr :: Ptr SExp}
newtype CipherHdPtr = CipherHdPtr { unCipherHdPtr :: Ptr CipherHd }
newtype GCryModulePtr = GCryModulePtr { unGCryModulePtr :: Ptr GCryModule }
newtype GCryMdHdPtr = GCryMdHdPtr {unGCryMdHdPtr :: Ptr GCryMdHd }

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
{#enum gcry_mpi_format as GCry_MPI_Format {} deriving (Eq)#}
{#enum gcry_mpi_flag as GCry_MPI_Flag {} deriving (Eq)#}
{#enum gcry_random_level as GCry_Random_Level {} deriving (Eq)#}

type GCry_Error = GPG_Error
type GCry_Err_Code = GPG_Err_Code
type GCry_Err_Source = GPG_Err_Source

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
        unMPIPtr `MPIPtr',
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
        id `MPI',
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
        unMPIPtr `MPIPtr'
    } -> `GCry_Error' fromIntegral#}
     
{#fun gcry_ac_data_get_name {
        id `ACData',
        fromIntegral `ACFlags',
        id `CString',
        unMPIPtr `MPIPtr'
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
        id `MPI'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_sign {
        id `ACHandle',
        id `ACKey',
        id `MPI',
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
        id `MPI',
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
        unMPIPtrPtr `MPIPtrPtr'
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
        id `CSizePtr'
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
        id `CSizePtr'
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

{#fun wrap_gcry_control_0 as gcry_control_0 {
        fromEnumInt `GCry_Ctl_Cmd'  
    } -> `GCry_Error' fromIntegral#}

{- 'const char *' commands:
    GCRYCTL_SET_RANDOM_SEED_FILE
    GCRYCTL_SET_RNDEGD_SOCKET
-}
{#fun wrap_gcry_control_constcharptr as gcry_control_constcharptr {
        fromEnumInt `GCry_Ctl_Cmd',
        id `CString'
    } -> `GCry_Error' fromIntegral#}

{- 'int' commands:
    GCRYCTL_SET_VERBOSITY
-}
{#fun wrap_gcry_control_int as gcry_control_int {
        fromEnumInt `GCry_Ctl_Cmd',
        id `CInt'
    } -> `GCry_Error' fromIntegral#}

{- 'unsigned int' commands:
    GCRYCTL_SET_DEBUG_FLAGS
    GCRYCTL_CLEAR_DEBUG_FLAGS
-}
{#fun wrap_gcry_control_uint as gcry_control_uint {
        fromEnumInt `GCry_Ctl_Cmd',
        id `CUInt'
    } -> `GCry_Error' fromIntegral#}

{- 'struct auth_ops *' commands:
    GCRYCTL_SET_THREAD_CBS
-}
{#fun wrap_gcry_control_voidptr as gcry_control_voidptr {
        fromEnumInt `GCry_Ctl_Cmd',
        id `Ptr ()'
    } -> `GCry_Error' fromIntegral#}

{- 'FILE *' commands:
   GCRYCTL_PRINT_CONFIG
-}
{#fun wrap_gcry_control_fileptr as gcry_control_fileptr {
        fromEnumInt `GCry_Ctl_Cmd',
        castPtr `Ptr CFile'
    } -> `GCry_Error' fromIntegral#}

{- End gcry_control -}

{#fun gcry_create_nonce {
        id `Ptr ()',
        fromIntegral `CSize'
    } -> `()'#}

{#fun wrap_gcry_err_code as gcry_err_code {
        fromIntegral `GCry_Error'
    } -> `GCry_Err_Code' toIntEnum#}

{#fun gcry_err_code_from_errno {
        id `CInt'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_err_code_to_errno {
        fromEnumInt `GCry_Err_Code'
    } -> `CInt' id#}

{#fun wrap_gcry_err_make as gcry_err_make {
        fromEnumInt `GCry_Err_Source',
        fromEnumInt `GCry_Err_Code'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_err_make_from_errno {
        fromEnumInt `GCry_Err_Source',
        id `CInt'
    } -> `GCry_Error' fromIntegral#}

{#fun wrap_gcry_err_source as gcry_err_source {
        fromIntegral `GCry_Error'
    } -> `GCry_Err_Source' toIntEnum#}

{#fun wrap_gcry_error as gcry_error {
        fromEnumInt `GCry_Err_Code'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_error_from_errno {
        id `CInt'
    } -> `GCry_Error' fromIntegral#}

{- Appears as though gcry_fips_mode_active is no longer used. -}

{#fun gcry_free {
        id `Ptr ()'
    } -> `()'#}

{#fun gcry_malloc {
        fromIntegral `CSize'
    } -> `()'#}

{#fun gcry_malloc_secure {
        fromIntegral `CSize'
    } -> `()'#}

{#fun gcry_md_algo_name {
        id `CInt'
    } -> `CString' id#}

{#fun gcry_md_close {
        id `GCryMdHd'
    } -> `()'#}

{#fun gcry_md_copy {
        unGCryMdHdPtr `GCryMdHdPtr',
        id `GCryMdHd'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_md_debug {
        id `GCryMdHd',
        id `CString'
    } -> `()'#}

{#fun gcry_md_enable {
        id `GCryMdHd',
        id `CInt'
    } -> `GCry_Error' fromIntegral#}

{#fun wrap_gcry_md_final as gcry_md_final {
        id `GCryMdHd'
    } -> `()'#}

{#fun gcry_md_get_algo {
        id `GCryMdHd'
    } -> `CInt' id#}

{#fun gcry_md_get_algo_dlen {
        id `CInt'
    } -> `CUInt' id#} 

{#fun wrap_gcry_md_get_asnoid as gcry_md_get_asnoid {
        id `CInt',
        id `Ptr ()',
        id `CSizePtr'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_md_hash_buffer {
        id `CInt',           -- Algo
        id `Ptr ()',         -- Digest
        id `Ptr ()',         -- Buffer
        fromIntegral `CSize' -- Length
    } -> `()'#}

{#fun gcry_md_is_enabled {
        id `GCryMdHd',
        id `CInt'
    } -> `CInt' id#} 

{#fun gcry_md_is_secure {
        id `GCryMdHd'
    } -> `CInt' id#} 

{#fun gcry_md_list {
        id `Ptr CInt', -- List
        id `Ptr CInt'  -- List Length
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_md_map_name {
        id `CString'
    } -> `CInt' id#} 

{#fun gcry_md_open {
        unGCryMdHdPtr `GCryMdHdPtr', -- hd
        id `CInt',                   -- algo
        id `CUInt'                   -- flags
    } -> `GCry_Error' fromIntegral#}

{#fun wrap_gcry_md_putc as gcry_md_putc {
        id `GCryMdHd',
        id `CInt'
    } -> `()'#}

{#fun gcry_md_read {
        id `GCryMdHd',
        id `CInt'
    } -> `Ptr CUChar' id#}

{#fun gcry_md_register {
        id `GCryMdSpec',
        id `Ptr CUInt',
        unGCryModulePtr `GCryModulePtr'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_md_reset {
        id `GCryMdHd'
    } -> `()'#}

{#fun gcry_md_setkey {
        id `GCryMdHd', -- hd
        id `Ptr ()',   -- key
        fromIntegral `CSize' -- keylen
    } -> `GCry_Error' fromIntegral#}

{#fun wrap_gcry_md_start_debug as gcry_md_start_debug {
        id `GCryMdHd', -- hd
        id `CString'
    } -> `()'#}

{#fun wrap_gcry_md_test_algo as gcry_md_test_algo {
        id `CInt'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_md_unregister {
        id `GCryModule'
    } -> `()'#}

{#fun gcry_md_write {
        id `GCryMdHd', -- hd
        id `Ptr ()',   -- buffer
        fromIntegral `CSize' -- length
    } -> `()'#}

-- w = u + v
{#fun gcry_mpi_add {
        id `MPI', -- w
        id `MPI', -- u
        id `MPI'  -- v
    } -> `()'#}

-- w = u + v
{#fun gcry_mpi_add_ui {
        id `MPI', -- w
        id `MPI', -- u
        id `CULong'   -- v
    } -> `()'#}

-- w = u + v mod M
{#fun gcry_mpi_addm {
        id `MPI', -- w
        id `MPI', -- u
        id `MPI', -- v
        id `MPI'  -- m
    } -> `()'#}

{#fun gcry_mpi_aprint {
        fromEnumInt `GCry_MPI_Format',
        id `Ptr (Ptr CUChar)',
        id `CSizePtr',
        id `MPI'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_mpi_clear_bit {
        id `MPI',
        id `CUInt'
    } -> `()'#}

{#fun gcry_mpi_clear_flag {
        id `MPI',
        fromEnumInt `GCry_MPI_Flag'
    } -> `()'#}

{#fun gcry_mpi_clear_highbit {
        id `MPI',
        id `CUInt'
    } -> `()'#}

-- u = v ->  0
-- u < v -> -1
-- u > v ->  1
{#fun gcry_mpi_cmp {
        id `MPI', -- u
        id `MPI'  -- v
    } -> `CInt' id#}

{#fun gcry_mpi_cmp_ui {
        id `MPI', -- u
        id `CULong' -- v
    } -> `CInt' id#}

{#fun gcry_mpi_copy {
        id `MPI'
    } -> `MPI' id#}

{#fun gcry_mpi_div {
        id `MPI', -- q
        id `MPI', -- r
        id `MPI', -- dividend
        id `MPI', -- divisor
        id `CInt'   -- round
    } -> `()'#}

{#fun gcry_mpi_dump {
        id `MPI'
    } -> `()'#}

{#fun gcry_mpi_gcd {
        id `MPI', -- g
        id `MPI', -- a
        id `MPI'  -- b
    } -> `CInt' id#}

{#fun gcry_mpi_get_flag {
        id `MPI',
        fromEnumInt `GCry_MPI_Flag'
    } -> `CInt' id#}

{#fun gcry_mpi_get_nbits {
        id `MPI'
    } -> `CUInt' id#}

{#fun gcry_mpi_get_opaque {
        id `MPI',
        id `Ptr CUInt'
    } -> `Ptr ()' id#}

{#fun gcry_mpi_invm {
        id `MPI', -- x
        id `MPI', -- a
        id `MPI'  -- m
    } -> `CInt' id#}

{- 1.4.1 doesn't implement lshift. TODO: implement in 1.4.4 -}

{#fun gcry_mpi_mod {
        id `MPI', -- r
        id `MPI', -- dividend
        id `MPI'  -- divisor
    } -> `()'#}

-- w = u * v
{#fun gcry_mpi_mul {
        id `MPI', -- w
        id `MPI', -- u
        id `MPI'  -- v
    } -> `()'#}

-- w = u * 2^e
{#fun gcry_mpi_mul_2exp {
        id `MPI', -- w
        id `MPI', -- u
        id `CULong' -- e
    } -> `()'#}

-- w = u * v
{#fun gcry_mpi_mul_ui {
        id `MPI', -- w
        id `MPI', -- u
        id `CULong' -- v
    } -> `()'#}

-- w = u * v `mod` m
{#fun gcry_mpi_mulm {
        id `MPI', -- w
        id `MPI', -- u
        id `MPI', -- v
        id `MPI'  -- m
    } -> `()'#}

{#fun gcry_mpi_new {
        id `CUInt'
    } -> `MPI' id#}

-- w = b^e `mod` m
{#fun gcry_mpi_powm {
        id `MPI', -- w
        id `MPI', -- b
        id `MPI', -- e
        id `MPI'  -- m
    } -> `()'#}

{#fun gcry_mpi_print {
        fromEnumInt `GCry_MPI_Format',
        id `Ptr CUChar',
        fromIntegral `CSize',
        id `CSizePtr',
        id `MPI'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_mpi_randomize {
        id `MPI',
        id `CUInt',
        fromEnumInt `GCry_Random_Level'
    } -> `()'#}

{#fun gcry_mpi_release {
        id `MPI'
    } -> `()'#}

{#fun gcry_mpi_rshift {
        id `MPI',
        id `MPI',
        id `CUInt'
    } -> `()'#}

{#fun gcry_mpi_scan {
        unMPIPtr `MPIPtr', -- r_mpi
        fromEnumInt `GCry_MPI_Format', -- format
        id `Ptr ()', -- buffer
        fromIntegral `CSize', -- buflen
        id `CSizePtr' -- nscanned
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_mpi_set {
        id `MPI',
        id `MPI'
    } -> `MPI' id#}

{#fun gcry_mpi_set_bit {
        id `MPI',
        id `CUInt'
    } -> `()'#}

{#fun gcry_mpi_set_flag {
        id `MPI',
        fromEnumInt `GCry_MPI_Flag'
    } -> `()'#}

{#fun gcry_mpi_set_highbit {
        id `MPI',
        id `CUInt'
    } -> `()'#}

{#fun gcry_mpi_set_opaque {
        id `MPI',
        id `Ptr ()',
        id `CUInt'
    } -> `MPI' id#}

{#fun gcry_mpi_set_ui {
        id `MPI',
        id `CULong'
    } -> `MPI' id#}

{#fun gcry_mpi_snew {
        id `CUInt'
    } -> `MPI' id#}

-- w = u - v
{#fun gcry_mpi_sub {
        id `MPI', -- w
        id `MPI', -- u
        id `MPI'  -- v
    } -> `()'#}

-- w = u - v
{#fun gcry_mpi_sub_ui {
        id `MPI', -- w
        id `MPI', -- u
        id `CULong'  -- v
    } -> `()'#}

-- w = u - v `mod` m
{#fun gcry_mpi_subm {
        id `MPI', -- w
        id `MPI', -- u
        id `MPI', -- v
        id `MPI'  -- m
    } -> `()'#}

{#fun gcry_mpi_swap {
        id `MPI',
        id `MPI'
    } -> `()'#}

{#fun gcry_mpi_test_bit {
        id `MPI',
        id `CUInt'
    } -> `CInt' id#}

{#fun gcry_pk_algo_info {
        id `CInt',
        id `CInt',
        id `Ptr ()',
        id `CSizePtr'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_pk_algo_name {
        id `CInt'
    } -> `CString' id#}

{#fun gcry_pk_ctl {
        id `CInt',
        id `Ptr ()',
        fromIntegral `CSize'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_pk_decrypt {
        unSExpPtr `SExpPtr', -- r_plain
        id `SExp',           -- data
        id `SExp'            -- skey
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_pk_encrypt {
        unSExpPtr `SExpPtr', -- r_ciph
        id `SExp',           -- data
        id `SExp'            -- pkey
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_pk_genkey {
        unSExpPtr `SExpPtr', -- r_key
        id `SExp'            -- params
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_pk_get_keygrip {
        id `SExp',      -- key
        id `Ptr CUChar' -- array
    } -> `Ptr CUChar' id#}

{#fun gcry_pk_get_nbits {
        id `SExp' -- key
    } -> `CUInt' id#}

{#fun gcry_pk_list {
        id `Ptr CInt',
        id `Ptr CInt'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_pk_map_name {
        id `CString'
    } -> `CInt' id#}

{#fun gcry_pk_register {
        id `GCryPkSpec', -- pubkey
        id `Ptr CUInt', -- algorithm id
        unGCryModulePtr `GCryModulePtr' -- module 
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_pk_sign {
        unSExpPtr `SExpPtr', -- r_sig
        id `SExp', -- data
        id `SExp'  -- skey
    } -> `GCry_Error' fromIntegral#}

{#fun wrap_gcry_pk_test_algo as gcry_pk_test_algo {
        id `CInt' -- algo
    } -> `CInt' id#}

{#fun gcry_pk_testkey {
        id `SExp' -- key
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_pk_unregister {
        id `GCryModule'
    } -> `()'#}

{#fun gcry_pk_verify {
        id `SExp', -- sig
        id `SExp', -- data
        id `SExp'  -- pkey
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_prime_check {
        id `MPI',
        fromIntegral `ACFlags'
    } -> `GCry_Error' fromIntegral#}

type PrimeCheckFun = FunPtr (Ptr () -> CInt -> MPI -> IO CInt)

{#fun gcry_prime_generate {
        unMPIPtr `MPIPtr', -- prime
        id `CUInt',            -- prime bits
        id `CUInt',            -- prime factor
        unMPIPtrPtr `MPIPtrPtr', -- factors
        id `PrimeCheckFun',    -- cb_func
        id `Ptr ()',           -- cb_arg
        fromEnumInt `GCry_Random_Level', -- random level
        fromIntegral `ACFlags'
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_prime_group_generator {
        unMPIPtr `MPIPtr', -- g
        id `MPI', -- prime
        unMPIPtr `MPIPtr', -- factors
        id `MPI' -- start
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_prime_release_factors {
        unMPIPtr `MPIPtr' -- factors
    } -> `()'#}

{#fun gcry_random_bytes {
        fromIntegral `CSize',
        fromEnumInt `GCry_Random_Level'
    } -> `Ptr ()' id#}

{#fun gcry_random_bytes_secure {
        fromIntegral `CSize',
        fromEnumInt `GCry_Random_Level'
    } -> `Ptr ()' id#}

{#fun gcry_randomize {
        id `Ptr ()', -- buffer
        fromIntegral `CSize', -- length
        fromEnumInt `GCry_Random_Level' -- level
    } -> `()'#}

{#fun gcry_realloc {
        id `Ptr ()', -- p
        fromIntegral `CSize' -- n
    } -> `Ptr ()' id#}

type FuncAlloc = FunPtr (CSize -> IO (Ptr ()))
type FuncAllocSecure = FunPtr (CSize -> IO (Ptr ()))
type FuncSecureCheck = FunPtr (Ptr () -> IO CInt)
type FuncRealloc = FunPtr (Ptr () -> CSize -> IO (Ptr ()))
type FuncFree = FunPtr (Ptr () -> IO ())

{#fun gcry_set_allocation_handler {
        castFunPtr `FuncAlloc',
        castFunPtr `FuncAllocSecure',
        id `FuncSecureCheck',
        castFunPtr `FuncRealloc',
        id `FuncFree'
    } -> `()'#}

type FuncError = FunPtr (Ptr () -> CInt -> Ptr CChar -> IO ())

{#fun gcry_set_fatalerror_handler {
        id `FuncError',
        id `Ptr ()' -- cb_data
    } -> `()'#}

{- TODO: This Breaks: va_list
{#fun gcry_set_log_handler {
    } -> `()'#}
    -}

type FunNoMem = FunPtr (Ptr () -> CSize -> CUInt -> IO CInt)

{#fun gcry_set_outofcore_handler {
        castFunPtr `FunNoMem',
        id `Ptr ()' -- cb_data
    } -> `()'#}

type FunProgress = FunPtr (Ptr () -> Ptr CChar -> CInt -> CInt -> CInt -> IO ())

{#fun gcry_set_progress_handler {
        id `FunProgress',
        id `Ptr ()'  -- cb_data
    } -> `()'#}

{- gcry_sexp_build uses varargs. Use gcry_sexp_build_array.
{#fun gcry_sexp_build {
        id `SExpPtr', -- sexp
    } -> `GCry_Error' fromIntegral#}
-}

{#fun gcry_sexp_build_array {
        unSExpPtr `SExpPtr', -- retsexp
        id `CSizePtr', -- erroff
        id `CString', -- format
        id `Ptr (Ptr ())' -- arg_list
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_sexp_canon_len {
        id `Ptr CUChar', -- buffer
        fromIntegral `CSize', -- length
        id `CSizePtr', -- erroff
        id `Ptr CUInt' -- errcode
    } -> `CSize' fromIntegral#}

{#fun gcry_sexp_car {
        id `SExp'
    } -> `SExp' id#}

{#fun gcry_sexp_cdr {
        id `SExp'
    } -> `SExp' id#}

type FunFreeFunc = FunPtr (Ptr () -> IO ())

{#fun gcry_sexp_create {
        unSExpPtr `SExpPtr', -- retsexp
        id `Ptr ()', -- buffer
        fromIntegral `CSize', -- length
        id `CInt', -- autodetect
        id `FunFreeFunc' -- freefnc
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_sexp_dump {
        id `SExp'
    } -> `()'#}

{#fun gcry_sexp_find_token {
        id `SExp',
        id `CString',
        fromIntegral `CSize'
    } -> `SExp' id#}

{#fun gcry_sexp_length {
        id `SExp'
    } -> `CInt' id#}

{#fun gcry_sexp_new {
        unSExpPtr `SExpPtr', -- retsexp
        id `Ptr ()', -- buffer
        fromIntegral `CSize', -- lenght
        id `CInt' -- autodetect
    } -> `GCry_Error' fromIntegral#}

{#fun gcry_sexp_nth {
        id `SExp', -- list
        id `CInt'  -- number
    } -> `SExp' id#}

{#fun gcry_sexp_nth_data {
        id `SExp', -- list
        id `CInt', -- number 
        id `CSizePtr' -- datalen
    } -> `CString' id#}

{#fun gcry_sexp_nth_mpi {
        id `SExp', -- list
        id `CInt', -- number
        id `CInt'  -- mpifmt
    } -> `MPI' id#}

{#fun gcry_sexp_nth_string {
        id `SExp', -- list
        id `CInt'  -- number
    } -> `CString' id#}

{#fun gcry_sexp_release {
        id `SExp'
    } -> `()'#}

{#fun gcry_sexp_sprint {
        id `SExp', -- sexp
        id `CInt', -- mode
        id `Ptr ()', -- buffer
        fromIntegral `CSize' -- maxlength
    } -> `CSize' fromIntegral#}

{#fun gcry_sexp_sscan {
        unSExpPtr `SExpPtr', -- retsexp
        id `CSizePtr', -- erroff
        id `CString', -- buffer
        fromIntegral `CSize'
    } -> `GCry_Error' fromIntegral#}

{- The following sexp functions aren't called out by the docs:

gcry_sexp_t gcry_sexp_cons (const gcry_sexp_t a, const gcry_sexp_t b);
gcry_sexp_t gcry_sexp_alist (const gcry_sexp_t *array);
gcry_sexp_t gcry_sexp_vlist (const gcry_sexp_t a, ...);
gcry_sexp_t gcry_sexp_append (const gcry_sexp_t a, const gcry_sexp_t n);
gcry_sexp_t gcry_sexp_prepend (const gcry_sexp_t a, const gcry_sexp_t n);
gcry_sexp_t gcry_sexp_cadr (const gcry_sexp_t list);

-}

{#fun gcry_strerror {
        fromIntegral `GCry_Error'
    } -> `CString' id#}

{#fun gcry_strsource {
        fromIntegral `GCry_Error'
    } -> `CString' id#}
