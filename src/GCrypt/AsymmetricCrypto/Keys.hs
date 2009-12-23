{-# LANGUAGE EmptyDataDecls #-}
module GCrypt.AsymmetricCrypto.Keys (
    ACKey,
    ACKeyPair,
    keyInit,
    keyPairGenerate,
    keyPairExtract,
) where

import Foreign.Ptr
import Foreign.C.Types

import GCrypt.Base
import GCrypt.Common
import GCrypt.Util


{- TODO: Implement this so keyPairGenerate has more flexibility.
typedef struct gcry_ac_key_spec_rsa
{
  gcry_mpi_t e;                 /* E to use.  */
} gcry_ac_key_spec_rsa_t;
-}

keyInit :: ACHandle -> ACKeyType -> ACData -> IO (Either GCry_Error ACKey)
keyInit h t d = do
    newWithChecked f checkData
    where
        f key = gcry_ac_key_init (ACKeyPtr key) h t d

keyPairGenerate :: ACHandle
                -> CUInt
                -- -> Maybe ACKeySpecRSA -- Taken out until supported
                -> IO (Either GCry_Error ACKeyPair)
keyPairGenerate h n {- s -} = do
    newWithChecked f checkData
    where
        {-
        s' = case s of
                  Nothing -> ACKeySpecRSAPtr nullPtr
                  Just _ -> error "keyPairGenerate currently does not support key specs"
        -}
        f kpair = gcry_ac_key_pair_generate h n (ACKeySpecRSAPtr nullPtr)
            (ACKeyPairPtr kpair)
            (MPIPtrPtr nullPtr)

keyPairExtract :: ACKeyPair -> ACKeyType -> IO ACKey
keyPairExtract = gcry_ac_key_pair_extract

keyDestroy :: ACKey -> IO ()
keyDestroy = gcry_ac_key_destroy

keyPairDestroy :: ACKeyPair -> IO ()
keyPairDestroy = gcry_ac_key_pair_destroy

keyDataGet :: ACKey -> IO ACData
keyDataGet = gcry_ac_key_data_get
