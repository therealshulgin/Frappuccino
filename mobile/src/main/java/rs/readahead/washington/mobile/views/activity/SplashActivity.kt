package rs.readahead.washington.mobile.views.activity

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import rs.readahead.washington.mobile.MyApplication
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.views.base_ui.BaseActivity

private const val SPLASH_TIMEOUT_MS = 1000L

class SplashActivity : BaseActivity() {

    private val handler by lazy { Handler(Looper.getMainLooper()) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.splash_layout)
        handler.postDelayed({
            goToMainActivity()
        }, SPLASH_TIMEOUT_MS)
    }

    private fun goToMainActivity() {
        MyApplication.startMainActivity(this@SplashActivity)
        finish()
    }
}
