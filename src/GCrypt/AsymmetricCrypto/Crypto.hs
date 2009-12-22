module GCrypt.AsymmetricCrypto.Crypto (
    dataEncrypt,
    dataDecrypt,
    dataSign,
    dataVerify,
    dataEMEEncode,
    dataEMSAEncode,

    OptionsEME(..),
    OptionsEMSA(..),
    MDAlgo(..),
) where

import GCrypt.Base
import GCrypt.Util
import GCrypt.Common
import GCrypt.AsymmetricCrypto.IO
import GCrypt.Generalities.Error.Strings
import GPG.Error

import Control.Monad
import Data.ByteString hiding (putStrLn)
import Data.ByteString.Unsafe

import Foreign.Ptr
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Utils
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

-- Cast a (Ptr ACIO) to an ACIOPtr
ptr2AP :: Ptr ACIO -> ACIOPtr
ptr2AP = ACIOPtr . castPtr

dataEMEEncode :: OptionsEME -> ByteString -> IO (Either String ByteString)
dataEMEEncode o@(OptionsEME sze) s | sze < 88 = return $ Left segfaultWarning
                                   | otherwise = genEncode o s AC_EME_PKCS_V1_5

dataEMSAEncode :: OptionsEMSA -> ByteString -> IO (Either String ByteString)
dataEMSAEncode o s = genEncode o s AC_EMSA_PKCS_V1_5

-- Generic encoding function since the interface is just about the same
-- for dataEMEEncode and dataEMSAEncode.
genEncode :: (Storable a) => a -> ByteString -> GCry_EncMethod -> IO (Either String ByteString)
genEncode o s m = do
    r_io <- initReadableByteString s
    w_io <- mkACIO

    let w_io' = unACIO w_io

    (ns,nl) <- withForeignPtr w_io' $ \w_io'' ->
        initWritableString (ptr2AP w_io'')

    ret <- with o $ \o' ->
        withForeignPtr2 (unACIO r_io) (unACIO w_io) $ \r' w' ->
            gcry_ac_data_encode m 0
                (castPtr o') (ptr2AP r') (ptr2AP w')

    case ret of 
        0 -> (s_l_2_bs ns nl) >>= return . Right
        _ -> strerror ret >>= return . Left

s_l_2_bs :: ForeignPtr (Ptr CUChar) -> ForeignPtr CULong -> IO ByteString
s_l_2_bs ns nl =
    withForeignPtr2 ns nl $ \ns' nl' -> do
        str <- peek ns'
        ln  <- peek nl'
        unsafePackCStringFinalizer (castPtr str)
                                   (fromIntegral ln)
                                   (gcry_free $ castPtr str)

segfaultWarning :: String
segfaultWarning = unlines [
    "Error: The size you passed to dataEMEEncode in OptionsEME is too short.",
    "libgcrypt would segfault if I allowed execution. I'm quitting now." ]
