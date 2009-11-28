module GCrypt.AsymmetricCrypto.Crypto (
    dataEncrypt,
    dataDecrypt,
    dataSign,
    dataVerify,
    dataEMEEncode,

    OptionsEME(..),
    OptionsEMSA(..),
) where

import GCrypt.Base
import GCrypt.Util
import GCrypt.Common
import GCrypt.AsymmetricCrypto.IO
import GPG.Error

import Control.Monad
import Data.Word
import Data.ByteString
import Data.ByteString.Unsafe

import Foreign.Ptr
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Utils
import Foreign.Marshal.Alloc
import Foreign.Storable

-- |Returns either an error or the encrypted data
-- inside an ACData.
dataEncrypt :: ACHandle -- | handle
            -> ACFlags  -- | flags
            -> ACKey    -- | key
            -> MPI      -- | data_plain
            -> IO (Either GCry_Error ACData)
dataEncrypt h f k m = do
    newWithChecked fn checkData
    where
        fn d = gcry_ac_data_encrypt h f k m (ACDataPtr d)

dataDecrypt :: ACHandle -- | handle
            -> ACFlags  -- | flags
            -> ACKey    -- | key
            -> ACData   -- | data_encrypted
            -> IO (Either GCry_Error MPI)
dataDecrypt h f k d = do
    newWithChecked fn checkData
    where
        fn m = gcry_ac_data_decrypt h f k (MPIPtr m) d

dataSign :: ACHandle -- | handle
         -> ACKey    -- | key
         -> MPI      -- | data_plain
         -> IO (Either GCry_Error ACData)
dataSign h k m = do
    newWithChecked fn checkData
    where
        fn d = gcry_ac_data_sign h k m (ACDataPtr d)

dataVerify :: ACHandle -- | handle
           -> ACKey    -- | key
           -> MPI      -- | data_plain
           -> ACData   -- | data_signature
           -> IO Bool  -- | True when the signature is verified.
dataVerify h k m d = do
    ret <- gcry_ac_data_verify h k m d
    return $ (toIntEnum ret) == GPG_ERR_NO_ERROR

dataEMEEncode :: OptionsEME -> ByteString -> IO (Either GCry_Error ByteString)
dataEMEEncode o s = do
    r_io <- initReadableByteString s
    w_io <- mkACIO

    let w_io' = unACIO w_io

    (ns,nl) <- withForeignPtr w_io' $ \w_io'' ->
        initWritableString (ACIOPtr $ castPtr w_io'')

    ret <- with o $ \o' ->
        withForeignPtr (unACIO r_io) $ \r' ->
            withForeignPtr (unACIO r_io) $ \w' ->
                gcry_ac_data_encode AC_EME_PKCS_V1_5 0
                    (castPtr o')
                    (ACIOPtr $ castPtr r')
                    (ACIOPtr $ castPtr w')
    case toIntEnum ret of 
        GPG_ERR_NO_ERROR -> (s_l_2_bs ns nl) >>= return . Right
        _                -> return $ Left ret

    where
        s_l_2_bs :: NewStringPtrRef -> NewStringLnPtrRef -> IO ByteString
        s_l_2_bs ns nl =
            withForeignPtr ns $ \ns' ->
            withForeignPtr nl $ \nl' -> do
                toFreeStr <- peek ns'
                toFreeLn  <- peek nl'
                str <- peek toFreeStr
                ln  <- peek toFreeLn
                unsafePackCStringFinalizer (castPtr str)
                                           (fromIntegral ln)
                                           (free toFreeStr >> free toFreeLn)

