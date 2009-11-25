module GCrypt.AsymmetricCrypto.Crypto (
    dataEncrypt,
    dataDecrypt,
    dataSign,
    dataVerify,
) where

import GCrypt.Base
import GCrypt.Util
import GCrypt.Common
import GPG.Error

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

-- I just discovered that dataEncode/dataDecode actually
-- never use the flags argument. I'm just passing zero
-- until the gcrypt authors decide they'll use it...

-- EME: Encoding Method for Encryption
-- EMSA: Encoding MEthod for Signatures with Appendix

{-
dataEMEEncode :: 
dataEMEDecode
dataEMSAEncode
-}

{- If you're looking for gcry_ac_data_*_scheme, stop. I don't currently
 - see a good reason to implement the GCrypt's IO objects (which would
 - require an inordinate amount of effort for something no one would
 - bother using (no, I can't back this up, just trust me)).
 -
 - So, yeah, don't bother. I'm not doing it. If some one else wants to,
 - I'd probably accept the patch. -}


