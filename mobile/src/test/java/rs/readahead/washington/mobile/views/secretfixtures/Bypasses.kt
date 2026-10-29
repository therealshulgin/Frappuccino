package rs.readahead.washington.mobile.views.secretfixtures

import android.content.Context
import android.widget.EditText
import android.widget.EditText as Box

// Negative controls for SecretInputLayoutTest: compiled with the unit tests and
// never run. Each object builds a plain text field in a way that a scan of
// simple names in the source does not see; the scan of the compiled classes
// must report every one of them. This package exists only in the tests, so the
// scan of the app's own classes never reads it.

typealias Field = EditText

/** Same simple name as the app's secret field, another package. */
class SecretEditText(context: Context) : EditText(context)

object ByImportAlias {
    fun make(c: Context): Any = Box(c)
}

object ByTypeAlias {
    fun make(c: Context): Any = Field(c)
}

object ByImpostor {
    fun make(c: Context): Any = SecretEditText(c)
}

object ByAnonymousSubclass {
    fun make(c: Context): Any = object : EditText(c) {}
}

object ByConstructorReference {
    fun make(c: Context): List<Any> = listOf(c).map(::EditText)
}
