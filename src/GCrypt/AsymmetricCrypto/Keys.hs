{-# LANGUAGE EmptyDataDecls #-}
module GCrypt.AsymmetricCrypto.Keys (
    ACKey,
    ACKeyPair,
    keyInit,
    keyPairGenerate,
    keyPairExtract,
    keyDestroy,
    keyPairDestroy,
    keyDataGet,
    keyTest,
    keyGetNBits,
    keyGetGrip,
) where

import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.C.Types

import Data.Word
import Data.ByteString.Internal

import GCrypt.Base
import GCrypt.Common
import GCrypt.Util

import GPG.Error

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

keyTest :: ACHandle -> ACKey -> IO GCry_Error
keyTest = gcry_ac_key_test

keyGetNBits :: ACHandle -> ACKey -> IO (Either GCry_Error Word32)
keyGetNBits h k = do
    r <- newWithChecked f checkData

    return $ case r of
                Left v  -> Left v
                Right v -> Right $ fromIntegral v
    where
        f :: Ptr CUInt -> IO GCry_Error
        f ptr = gcry_ac_key_get_nbits h k ptr

keyGetGrip :: ACHandle -> ACKey -> IO (Either GCry_Error ByteString)
keyGetGrip h k = do
    fp <- mallocForeignPtrBytes numBytes
    r <- withForeignPtr fp $ \p -> gcry_ac_key_get_grip h k p
    case (toIntEnum r) of
        GPG_ERR_NO_ERROR -> return . Right $ mkBS fp
        _                -> return $ Left r
    where
        mkBS p = fromForeignPtr (castForeignPtr p) 0 numBytes
        numBytes = 20
