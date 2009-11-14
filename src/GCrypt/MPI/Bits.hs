module GCrypt.MPI.Bits (
    getNBits,
    testBit,
    setBit,
    clearBit,
    setHighBit,
    clearHighBit,
    rshift,
    
    module Foreign.C.Types,
) where

import GCrypt.Base
import Foreign.C.Types

getNBits :: MPI -> IO CUInt
getNBits = gcry_mpi_get_nbits

testBit :: MPI -> CUInt -> IO CInt
testBit = gcry_mpi_test_bit

setBit :: MPI -> CUInt -> IO ()
setBit = gcry_mpi_set_bit

clearBit :: MPI -> CUInt -> IO ()
clearBit = gcry_mpi_clear_bit

setHighBit :: MPI -> CUInt -> IO ()
setHighBit = gcry_mpi_set_highbit

clearHighBit :: MPI -> CUInt -> IO ()
clearHighBit = gcry_mpi_clear_highbit

rshift :: MPI -> MPI -> CUInt -> IO ()
rshift = gcry_mpi_rshift

{- This wasn't defined in older versions
 - for some reason...
lshift :: MPI -> CUInt -> IO ()
lshift = gcry_mpi_lshift
-}
