package uk.gov.android.securestore

import java.lang.Exception

class SecureStorageError(
    exception: Exception
) : Error(exception)
