{-# LANGUAGE ForeignFunctionInterface #-}

module GCrypt where

import Foreign.C.Types
import Foreign.Ptr
import Foreign.Storable

#include "gcrypt.h"

--| This type represents a `handle' that is needed by functions
--  performing cryptographic operations. 
{#pointer gcry_ac_handle_t newtype#}

--| Destroy an ac handle. 
{#fun gcry_ac_close
    {id `AC'} -> `()' #}
