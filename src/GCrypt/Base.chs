{-# LANGUAGE ForeignFunctionInterface,
             GeneralizedNewtypeDeriving #-}
{-# OPTIONS -fno-warn-unused-binds #-}

module GCrypt.Base where

import Foreign.C.Types
import Foreign.Ptr

import Data.Word

import GPG.Error

#include "gcrypt.h"

-- |This type represents a `handle' that is needed by functions
-- performing cryptographic operations. 
{#pointer gcry_ac_handle_t as ACHandle newtype#}

-- |This type represents a `data set'.
{#pointer gcry_ac_data_t as ACData newtype#}
newtype ACDataPtr = ACDataPtr {unACDataPtr :: Ptr ACData}

{#pointer *gcry_ac_io_t as ACIO newtype#}

{#pointer gcry_ac_key_t as ACKey newtype #}

{#pointer gcry_mpi_t as ACMPI newtype #}
newtype ACMPIPtr = ACMPIPtr {unACMPIPtr :: Ptr ACMPI}

{#enum gcry_ac_em_t as GCry_EncMethod {} deriving (Eq)#}
{#enum gcry_ac_scheme_t as GCry_Scheme {} deriving (Eq)#}

type GCry_Options = Ptr ()
type GCry_Error = GPG_Error

newtype ACFlags = ACFlags Word32
    deriving (Integral,Real,Enum,Num,Ord,Eq,Show)

-- |Destroy an ac handle. 
{#fun gcry_ac_close
    {id `ACHandle'} -> `()' #}

-- |Destroy any values contained in the data set DATA.
{#fun gcry_ac_data_clear
    {id `ACData'} -> `()' #}

-- |Create a copy of the data set DATA (second arg) and store it in DATA_CP (first arg).
{#fun gcry_ac_data_copy
    {unACDataPtr `ACDataPtr', id `ACData'} -> `GCry_Error' fromIntegral#}

-- |Decodes a message according to the encoding method METHOD. OPTIONS
-- must be a pointer to a method-specific structure (gcry_ac_em*_t).
{#fun gcry_ac_data_decode
    {fromEnumInt `GCry_EncMethod',
     fromIntegral `ACFlags',
     id `GCry_Options',
     id `ACIO',
     id `ACIO'} -> `GCry_Error' fromIntegral#}

-- |Decrypt the decrypted data contained in the data set DATA_ENCRYPTED
-- with the key KEY under the control of the flags FLAGS and store the
-- resulting plain text MPI value in DATA_PLAIN.
{#fun gcry_ac_data_decrypt
    {id `ACHandle',
     fromIntegral `ACFlags',
     id `ACKey',
     unACMPIPtr `ACMPIPtr',
     id `ACData'} -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_decrypt_scheme
    {id `ACHandle',
     fromEnumInt `GCry_Scheme',
     fromIntegral `ACFlags',
     id `GCry_Options',
     id `ACKey',
     id `ACIO',
     id `ACIO'} -> `GCry_Error' fromIntegral#}

{#fun gcry_ac_data_destroy
    {id `ACData'} -> `()'#}

{#fun gcry_ac_data_encode
    {fromEnumInt `GCry_EncMethod',
     fromIntegral `ACFlags',
     id `GCry_Options',
     id `ACIO',
     id `ACIO'} -> `GCry_Error' fromIntegral#}

-- some necessary but annoying functions
fromEnumInt :: (Num b, Enum a) => a -> b
fromEnumInt = fromIntegral . fromEnum
