module GCrypt.Util (
    fromEnumInt,
    toIntEnum,
    newWith,
    newWith2,
    ULong,
) where

import Foreign.Storable
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Foreign.C.Types

type ULong = CULong

{- Helper functions to help marshal. -}
fromEnumInt :: (Num b, Enum a) => a -> b
fromEnumInt = fromIntegral . fromEnum

toIntEnum :: (Integral a, Enum b) => a -> b
toIntEnum = toEnum . fromIntegral

-- |Often times, we need to allocate something and
-- pass it to a function and keep the allocated object
-- around. The function we pass it to is the initializer.
newWith :: Storable a => (Ptr a -> IO b) -> IO (a,b)
newWith f = do
    p <- malloc
    r <- f p
    p' <- peek p
    free p
    return (p',r)

newWith2 :: (Storable a, Storable b) =>
            (Ptr a -> Ptr b -> IO c) -> IO (a,b,c)
newWith2 f = do
    p1 <- malloc
    p2 <- malloc
    r <- f p1 p2
    p1' <- peek p1
    p2' <- peek p2
    free p1
    free p2
    return (p1',p2',r)
