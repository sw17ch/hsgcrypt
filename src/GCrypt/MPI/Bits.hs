module GCrypt.MPI.Bits (
    getNBits,
    testBit,
    setBit,
    
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
