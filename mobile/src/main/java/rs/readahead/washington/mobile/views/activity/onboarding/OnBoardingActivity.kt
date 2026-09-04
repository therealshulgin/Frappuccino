package rs.readahead.washington.mobile.views.activity.onboarding

import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import androidx.core.content.ContextCompat
import androidx.core.view.get
import androidx.core.view.isVisible
import androidx.core.view.size
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentManager
import androidx.lifecycle.Lifecycle
import androidx.viewpager2.adapter.FragmentStateAdapter
import com.google.android.material.tabs.TabLayoutMediator
import rs.readahead.washington.mobile.util.IS_FROM_SETTINGS
import rs.readahead.washington.mobile.util.IS_ONBOARD_LOCK_SET
import dagger.hilt.android.AndroidEntryPoint
import org.hzontal.shared_ui.utils.DialogUtils
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.data.sharedpref.Preferences
import rs.readahead.washington.mobile.databinding.ActivityOnboardingBinding
import rs.readahead.washington.mobile.views.base_ui.BaseActivity
import timber.log.Timber

private const val ONBOARDING_INTRODUCTION_VIEW_INDEX = 0
private const val ONBOARDING_CAMERA_VIEW_INDEX = 1
private const val ONBOARDING_RECORDER_VIEW_INDEX = 2
private const val ONBOARDING_ZERO_KNOWLEDGE_VIEW_INDEX = 3
private const val ONBOARDING_LOCK_VIEW_INDEX = 4

@AndroidEntryPoint
class OnBoardingActivity : BaseActivity(), OnBoardActivityInterface {

    private var viewpagerItemsCount = 0
    private val isFromSettings by lazy { intent.getBooleanExtra(IS_FROM_SETTINGS, false) }
    private val isOnboardLockSet by lazy { intent.getBooleanExtra(IS_ONBOARD_LOCK_SET, false) }
    private lateinit var binding: ActivityOnboardingBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityOnboardingBinding.inflate(layoutInflater)

        overridePendingTransition(
            R.anim.`in`, R.anim.out
        )
        setContentView(binding.root)

        if (!isOnboardLockSet && !isFromSettings) initViewPager(4)

        initButtons()

        // Phase 6.1.16 - when the identity-setup chain is fully popped (back to
        // the intro ViewPager), restore the pager + global nav buttons that
        // goToIdentitySetup() hid on entry.
        supportFragmentManager.addOnBackStackChangedListener {
            if (!isOnboardLockSet && !isFromSettings) {
                // Chain fragments are opaque and cover the (still-visible) pager;
                // only toggle the chrome (global nav + tab dots) that draws on top.
                val inChain = supportFragmentManager.backStackEntryCount > 0
                binding.viewPager.visibility = if (inChain) View.GONE else View.VISIBLE
                showButtons(isNextButtonVisible = !inChain, isBackButtonVisible = !inChain)
                binding.tabLayout.isVisible = !inChain
            }
        }

        if (isOnboardLockSet) {
            Preferences.setFirstStart(false)
            replaceFragmentNoAddToBackStack(OnBoardLockSetFragment(), R.id.rootOnboard)
            hideViewpager()
        } else {
            if (isFromSettings) {
                replaceFragmentNoAddToBackStack(
                    OnBoardLockFragment.newInstance(isFromSettings),
                    R.id.rootOnboard
                )
                hideViewpager()
            }
        }
    }

    private fun initButtons() {
        binding.backBtn.setOnClickListener {
            onBackPressed()
        }
        binding.nextBtn.setOnClickListener {
            onNextPressed()
        }
    }

    override fun initProgress(itemCount: Int) {
        setupIndicators(itemCount)
    }

    private fun setupIndicators(indicatorCount: Int) {
        binding.indicatorsContainer.removeAllViews()
        val indicators = arrayOfNulls<ImageView>(indicatorCount)
        val layoutParams: LinearLayout.LayoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT
        )
        layoutParams.setMargins(12, 0, 12, 0)
        for (i in indicators.indices) {
            indicators[i] = ImageView(applicationContext)
            indicators[i].apply {
                this?.setImageDrawable(
                    ContextCompat.getDrawable(
                        applicationContext, R.drawable.onboarding_indicator_inactive
                    )
                )
                this?.layoutParams = layoutParams
            }
            binding.indicatorsContainer.addView(indicators[i])
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        // Observabilité bug "phrase perdue". On veut savoir
        // depuis quel fragment le back a ete pousse + l'etat du backstack,
        // pour correler avec les events MnemonicHolder.set/clear.
        val topFragment = supportFragmentManager.fragments
            .lastOrNull { it.isVisible }
            ?.javaClass?.simpleName ?: "<none>"
        Timber.tag("OnboardBack").d(
            "onBackPressed: backStackCount=%d, top=%s, mnemonicPresent=%b",
            supportFragmentManager.backStackEntryCount,
            topFragment,
            MnemonicHolder.isPresent
        )
        // Phase 6.1.16 - when the V2 identity-setup chain is on the back stack
        // (recovery phrase -> confirm -> PIN, overlay fragments over the intro
        // ViewPager), back must pop the overlay, not silently rewind the hidden
        // ViewPager underneath (which left the user stuck on the same screen and
        // re-showed the global nav buttons).
        if (supportFragmentManager.backStackEntryCount > 0) {
            supportFragmentManager.popBackStackImmediate()
            return
        }
        if (binding.viewPager.currentItem == 0) {
            super.onBackPressed()
        } else {
            if (binding.viewPager.size > 0)
                binding.viewPager.currentItem -= 1
        }
    }

    fun onNextPressed() {
        val lastIndex = viewpagerItemsCount - 1
        if (binding.viewPager.currentItem < lastIndex) {
            binding.viewPager.currentItem += 1
        } else {
            // Phase 6.1.16 - last intro page: enter the V2 identity-setup chain
            // (recovery phrase -> confirm -> PIN). The legacy Tella lock-method
            // chooser page (OnBoardLockFragment) is no longer in the pager.
            goToIdentitySetup()
        }
    }

    /**
     * Phase 6.1.16 - bridge from the intro ViewPager into the V2 identity-setup
     * chain. Hides the pager + the global nav buttons (so the chain's own
     * back/next are the only controls) and adds the mnemonic-generate fragment.
     */
    fun goToIdentitySetup() {
        hideViewpager()
        showButtons(isNextButtonVisible = false, isBackButtonVisible = false)
        binding.tabLayout.isVisible = false
        addFragment(OnBoardMnemonicGenerateFragment(), R.id.rootOnboard)
    }

    override fun setCurrentIndicator(index: Int) {
        val childCount = binding.indicatorsContainer.childCount
        for (i in 0 until childCount) {
            val imageView = binding.indicatorsContainer[i] as ImageView
            if (i == index) {
                imageView.setImageDrawable(
                    ContextCompat.getDrawable(
                        applicationContext, R.drawable.onboarding_indicator_active
                    )
                )
            } else {
                imageView.setImageDrawable(
                    ContextCompat.getDrawable(
                        applicationContext, R.drawable.onboarding_indicator_inactive
                    )
                )
            }
        }
    }

    override fun hideProgress() {
        binding.indicatorsContainer.visibility = View.INVISIBLE
    }

    override fun showProgress() {
        binding.indicatorsContainer.visibility = View.VISIBLE
    }

    override fun initViewPager(itemCount: Int) {
        viewpagerItemsCount = itemCount
        val pagerAdapter = ScreenSlidePagerAdapter(supportFragmentManager, this.lifecycle)
        binding.viewPager.adapter = pagerAdapter
        TabLayoutMediator(binding.tabLayout, binding.viewPager) { _, _ ->
        }.attach()

        binding.viewPager.visibility = View.VISIBLE
    }

    override fun enableSwipe(isSwipeable: Boolean, isTabLayoutVisible: Boolean) {
        binding.viewPager.isUserInputEnabled = isSwipeable
        binding.tabLayout.isVisible = isTabLayoutVisible
    }

    override fun showButtons(isNextButtonVisible: Boolean, isBackButtonVisible: Boolean) {
        binding.nextBtn.isVisible = isNextButtonVisible
        binding.backBtn.isVisible = isBackButtonVisible
    }

    override fun hideViewpager() {
        binding.viewPager.visibility = View.GONE
    }

    private inner class ScreenSlidePagerAdapter(fm: FragmentManager, lifecycle: Lifecycle) :
        FragmentStateAdapter(fm, lifecycle) {

        override fun getItemCount(): Int = viewpagerItemsCount
        override fun createFragment(position: Int): Fragment {
            val fragment: Fragment = when (position) {
                ONBOARDING_INTRODUCTION_VIEW_INDEX -> OnBoardIntroFragment()
                ONBOARDING_CAMERA_VIEW_INDEX -> OnBoardCameraFragment()
                ONBOARDING_RECORDER_VIEW_INDEX -> OnBoardRecorderFragment()
                ONBOARDING_ZERO_KNOWLEDGE_VIEW_INDEX -> OnBoardFilesFragment()
                ONBOARDING_LOCK_VIEW_INDEX -> OnBoardLockFragment()
                else -> OnBoardIntroFragment()
            }
            return fragment
        }
    }
}
