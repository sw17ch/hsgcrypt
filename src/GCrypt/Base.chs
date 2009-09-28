{-# LANGUAGE ForeignFunctionInterface #-}

module GCrypt.Base where

import Foreign.C.Types
import Foreign.Ptr
import Foreign.Storable

#include "gcrypt.h"

-- |This type represents a `handle' that is needed by functions
-- performing cryptographic operations. 
{#pointer gcry_ac_handle_t as ACHandle newtype#}

-- |This type represents a `data set'.
{#pointer gcry_ac_data_t as ACData newtype#}

-- |Destroy an ac handle. 
{#fun gcry_ac_close
    {id `ACHandle'} -> `()' #}

-- |Destroy any values contained in the data set DATA.
{#fun gcry_ac_data_clear
    {id `ACData'} -> `()' #}
