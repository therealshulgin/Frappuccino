package rs.readahead.washington.mobile.util

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.util.TypedValue
import android.view.View
import android.view.accessibility.AccessibilityManager
import androidx.fragment.app.FragmentManager
import com.google.gson.Gson
import com.google.gson.JsonParseException
import com.google.gson.reflect.TypeToken
import timber.log.Timber

fun <T> String.fromJsonToObjectList(clazz: Class<T>?): List<T>? {
    return try {
        val typeOfT = TypeToken.getParameterized(MutableList::class.java, clazz).type
        return Gson().fromJson(this, typeOfT)
    } catch (e: JsonParseException) {
        Timber.e(e)
        null
    }
}

fun Int.dpToPx(context: Context): Int {
    val metrics = context.resources.displayMetrics
    return TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, this.toFloat(), metrics).toInt()
}

fun View.hide() {
    visibility = View.GONE
}

fun FragmentManager.setupForAccessibility(context: Context) {
    if (context.isScreenReaderOn())
        addOnBackStackChangedListener {
            val lastFragmentWithView = fragments.last { it.view != null }
            for (fragment in fragments) {
                if (fragment == lastFragmentWithView) {
                    fragment.view?.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_YES
                } else {
                    fragment.view?.importantForAccessibility =
                        View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
                }
            }
        }
}

fun Context.isScreenReaderOn(): Boolean {
    val accessibilityManager =
        getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
    if (accessibilityManager != null && accessibilityManager.isEnabled) {
        val serviceInfoList =
            accessibilityManager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_SPOKEN)
        if (serviceInfoList.isNotEmpty())
            return true
    }
    return false
}
