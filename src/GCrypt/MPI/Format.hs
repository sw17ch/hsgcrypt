module GCrypt.MPI.Format (
    mpiScan,
    mpiScanBS,
    mpiPrint, -- unsafe
    mpiAPrint,
    mpiDump,
) where

import GCrypt.Util

import GPG.Error
import GCrypt.Base
import Foreign.Ptr
import Foreign.C.Types
import Foreign.Storable

import Data.ByteString
import Data.ByteString.Unsafe

-- Reads from buffer with specified format into a new MPI. Returns
-- (new mpi, number bytes scanned from buffer).
mpiScan :: MPIFormat -> Ptr () -> Int -> IO (Either GCry_Error (MPI,Int))
mpiScan format buffer buflen = do
    (mpi,nscanned,ret) <- newWith2 f

    -- castPtr is doing Ptr CSizePtr -> Ptr CSize
    n <- peek $ castPtr $ unCSizePtr nscanned
    case toIntEnum ret of
         GPG_ERR_NO_ERROR -> return $ Right (mpi, n)
         _ -> return $ Left ret
    where
        f :: Ptr MPI -> Ptr CSizePtr -> IO GCry_Error
        f m n = gcry_mpi_scan (MPIPtr m)
                              format
                              buffer
                              (fromIntegral buflen)
                              (CSizePtr n)

mpiScanBS :: MPIFormat -> ByteString -> IO (Either GCry_Error (MPI,Int))
mpiScanBS f b = do
    -- castPtr is doing Ptr Char -> Ptr ()
    unsafeUseAsCStringLen b $ \(s,l) -> mpiScan f (castPtr s) l

mpiPrint :: MPIFormat -> Ptr () -> CSize -> CSizePtr -> MPI -> IO GCry_Error
mpiPrint f b s sp m = gcry_mpi_print f (castPtr b) s sp m

mpiAPrint :: MPIFormat -> MPI -> IO (Either GCry_Error (Ptr (),Int))
mpiAPrint fmt mpi = do
    (buf,len,ret) <- newWith2 f

    case toIntEnum ret of
        -- castPtr is doing Ptr CUChar -> Ptr ()
        GPG_ERR_NO_ERROR -> return $ Right (castPtr buf, fromIntegral len)
        _ -> return $ Left ret
    where
        f :: Ptr (Ptr CUChar) -> Ptr CSize -> IO GCry_Error
        -- castPtr is doing Ptr CSize -> Ptr CSizePtR
        f b s = gcry_mpi_aprint fmt b (CSizePtr $ castPtr s) mpi

mpiDump :: MPI -> IO ()
mpiDump m = gcry_mpi_dump m
