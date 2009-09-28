{-# LANGUAGE ForeignFunctionInterface,
             GeneralizedNewtypeDeriving #-}

module GPG.Error where

import Data.Word

#include "gpg-error.h"

{#enum gpg_err_source_t as GPG_Err_Source {} deriving (Eq) #}
{#enum gpg_err_code_t as GPG_Err_Code {} deriving (Eq) #}

newtype GPG_Error = GPG_Error Word32
    deriving (Eq,Show,Num)
