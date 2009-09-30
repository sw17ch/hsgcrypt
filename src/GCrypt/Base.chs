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

-- Sometimes we need pointers-to-pointers
newtype ACDataPtr = ACDataPtr {unACDataPtr :: Ptr ACData}
newtype ACIOPtr = ACIOPtr {unACIOPtr :: Ptr ACIO}
newtype ACMPIPtr = ACMPIPtr {unACMPIPtr :: Ptr ACMPI}
newtype SExpPtr = SExpPtr {unSExpPtr :: Ptr SExp}

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
        id `CUInt'
    } -> `()'#}

{#fun gcry_ac_io_init_writable_string {
        id `ACIO',
        id `Ptr (Ptr CUChar)',
        id `Ptr CUInt'
    } -> `()'#}

type ReadableCallback = Ptr () -> Ptr CUChar -> Ptr CUInt -> IO CUInt
{#fun gcry_ac_io_init_readable_callback {
        id `ACIO',
        id `FunPtr ReadableCallback',
        id `Ptr ()'
    } -> `()'#}

type WritableCallback = Ptr () -> Ptr CUChar -> CUInt -> IO CUInt
{#fun gcry_ac_io_init_writable_callback {
        id `ACIO',
        id `FunPtr WritableCallback',
        id `Ptr ()'
    } -> `()'#}

{- Helper functions to help marshal. -}
fromEnumInt :: (Num b, Enum a) => a -> b
fromEnumInt = fromIntegral . fromEnum
