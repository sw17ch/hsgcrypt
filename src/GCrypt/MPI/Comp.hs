module GCrypt.MPI.Comp (
    cmp,
    cmpUi,
) where

import GCrypt.Base
import GCrypt.Util

cmp :: MPI -> MPI -> IO Ordering
cmp u v = gcry_mpi_cmp u v >>= return . int2ord

cmpUi :: MPI -> ULong -> IO Ordering
cmpUi u v = gcry_mpi_cmp_ui u v >>= return . int2ord

int2ord :: Integral a => a -> Ordering
int2ord a | a < 0 = LT
          | a == 0 = EQ
          | otherwise = GT
