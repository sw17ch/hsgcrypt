module GCrypt.Util (
    fromEnumInt,
    toIntEnum,
    newWith,
    newWithChecked,
    newWith2,
    newWith2Checked,
    ULong,
    catchToMaybe,

    withForeignPtr2,
) where

import Foreign.Storable
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.C.Types

import Control.Monad

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

-- |When `c` is True, we return `Right ptr`.
-- When `c` is False, we return `Left ret`.
newWithChecked :: (Storable a) => (Ptr a -> IO b) -> (b -> Bool) -> IO (Either b a)
newWithChecked f c = do
    (p,r) <- newWith f
    return $ case c r of
                  True -> Right p
                  False -> Left r

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

newWith2Checked :: (Storable a, Storable b) =>
                   (Ptr a -> Ptr b -> IO c) -> (c -> Bool) -> IO (Either c (a, b))
newWith2Checked f c = do
    (a,b,r) <- newWith2 f
    return $ case c r of
                  True -> Right (a,b)
                  False -> Left r

catchToMaybe :: (IO a) -> IO (Maybe a)
catchToMaybe a = catch (liftM Just a) (\_ -> return Nothing)

withForeignPtr2 :: ForeignPtr a
                -> ForeignPtr b
                -> (Ptr a -> Ptr b -> IO c)
                -> IO c
withForeignPtr2 p1 p2 e = withForeignPtr p1 $ \ p1' ->
                          withForeignPtr p2 $ \ p2' -> e p1' p2'
