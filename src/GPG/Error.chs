{-# LANGUAGE ForeignFunctionInterface,
             GeneralizedNewtypeDeriving #-}

module GPG.Error where

import Data.Word

#include "gpg-error.h"


{#enum gpg_err_code_t as GPG_Err_Code {} deriving (Eq) #}
{#enum gpg_err_source_t as GPG_Err_Source {} deriving (Eq) #}

-- gpg_error_t is typedef'ed to unsigned int 
newtype GPG_Error = GPG_Error Word32
    deriving (Eq,Show,Num,Integral,Real,Enum,Ord)
