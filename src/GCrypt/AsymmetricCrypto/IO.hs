module GCrypt.AsymmetricCrypto.IO (
    initReadableString,
    initWritableString,
    initReadableByteString,
    ACIOPtr,
    ACIO(..),
    mkACIO,
) where

import Foreign.Ptr
import Foreign.C.Types
import Foreign.ForeignPtr
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe

import GCrypt.Base

-- | the constructor should only ever be called from mkACIO.
newtype ACIO = ACIO { unACIO :: ForeignPtr ACIO }
    deriving (Show)

mkACIO :: IO ACIO
mkACIO = mallocForeignPtrBytes sizeOfACIO >>= return . ACIO

initReadableString :: ACIOPtr -> Ptr CUChar -> CULong -> IO ()
initReadableString = gcry_ac_io_init_readable_string

initReadableByteString :: ByteString -> IO ACIO
initReadableByteString bs = unsafeUseAsCStringLen bs f
    where
        f (s,l) = do
            a <- mkACIO
            withForeignPtr (unACIO a) $ \a' ->
                initReadableString (ACIOPtr (castPtr a'))
                                   (castPtr s)
                                   (fromIntegral l)
            return a

initWritableString :: ACIOPtr -> IO (ForeignPtr (Ptr CUChar),ForeignPtr CULong)
initWritableString p = do
    s <- mallocForeignPtr :: IO (ForeignPtr (Ptr CUChar))
    l <- mallocForeignPtr :: IO (ForeignPtr CULong)

    withForeignPtr s $ \s' -> withForeignPtr l $ \l' ->
        gcry_ac_io_init_writable_string p s' l'

    return (s,l)
