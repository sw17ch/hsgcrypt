module Main where

import Data.ByteString.Char8

import GCrypt
import GCrypt.AsymmetricCrypto.Crypto

main :: IO ()
main = withGCrypt $ do
    e <- dataEMEEncode (OptionsEME 512) str
    print e
    where
        str = pack "Hello World"
