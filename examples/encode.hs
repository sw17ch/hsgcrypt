module Main where

import Data.ByteString.Char8

import GCrypt.AsymmetricCrypto.Crypto

main :: IO ()
main = do
    e <- dataEMEEncode (OptionsEME 64) str
    print e
    where
        str = pack "Hello World"
