{-# LANGUAGE ForeignFunctionInterface,
             GeneralizedNewtypeDeriving #-}

module GCrypt.Base where

import Foreign.C.Types
import Foreign.Ptr
import Foreign.Storable

import Data.Word

import GPG.Error

#include "gcrypt.h"

-- |This type represents a `handle' that is needed by functions
-- performing cryptographic operations. 
{#pointer gcry_ac_handle_t as ACHandle newtype#}

-- |This type represents a `data set'.
{#pointer gcry_ac_data_t as ACData newtype#}

-- |Sometimes we need to give gcrypt pointers to pointers
-- so that it can manage the memory behind.
newtype ACDataPtr = ACDataPtr {unACDataPtr :: Ptr ACData}

{#pointer *gcry_ac_io_t as ACIO newtype#}

{#enum gcry_ac_em_t as GCry_EncMethod {} deriving (Eq)#}

type GCry_Options = Ptr ()
type GCry_Error = GPG_Error

newtype DecodeFlags = DecodeFlags Word32
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
     fromIntegral `DecodeFlags',
     id `GCry_Options',
     id `ACIO',
     id `ACIO'} -> `GCry_Error' fromIntegral#}

fromEnumInt :: (Num b, Enum a) => a -> b
fromEnumInt = fromIntegral . fromEnum
