module GCrypt.Common (
    checkData,
) where

import GCrypt.Base
import GCrypt.Util
import GPG.Error

-- |Things common to the inner workings of the library, not to be
-- exposed to the real world.


-- Helper for newWithChecked. If the error returned
-- is GPG_ERR_NO_ERROR, then we return the pointer,
-- else we return the error number.
checkData :: GCry_Error -> Bool
checkData e = (toIntEnum e) == GPG_ERR_NO_ERROR
