package rs.readahead.washington.mobile.views.activity.onboarding

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import org.hzontal.shared_ui.buttons.InformationButton
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.util.IS_FROM_SETTINGS
import rs.readahead.washington.mobile.views.base_ui.BaseFragment

/**
 * OnBoardLockFragment — legacy Tella onboarding info page, no longer part of
 * the intro ViewPager.
 *
 * Do not delete it as dead code. `OnBoardingActivity.initViewPager(4)` only
 * creates positions 0..3, so the pager's `ONBOARDING_LOCK_VIEW_INDEX = 4`
 * branch is never reached — but the entry from Settings (`isFromSettings`)
 * still displays this fragment, and that path is live.
 *
 * Phase 6.1.16 — V2 has a single lock method: the PIN, set later in
 * [OnBoardSetPinFragment] after the BIP-39 recovery phrase. The legacy Tella
 * lock-method chooser (PIN / pattern / password, each launching a Tella
 * Set*Activity) is gone, which is why the layout still declares three method
 * buttons while only one is wired: do not revive the pattern and password
 * ones, the activities they used to launch are no longer in the repo. This
 * page now simply bridges into the V2 identity-setup chain (recovery phrase ->
 * confirm -> PIN -> enrollment), exactly like [OnBoardLockSetFragment] does
 * for the post-panic / re-enroll path.
 */
class OnBoardLockFragment : BaseFragment() {
    private lateinit var lockPasswordBtn: InformationButton
    private lateinit var lockPINdBtn: InformationButton
    private lateinit var lockPatternBtn: InformationButton
    private var isFromSettings = false
    private lateinit var cancelBtn: TextView

    companion object {
        fun newInstance(isFromSettings: Boolean): OnBoardLockFragment {
            val args = Bundle()
            args.putBoolean(IS_FROM_SETTINGS, isFromSettings)
            val fragment = OnBoardLockFragment()
            fragment.arguments = args
            return fragment
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        return inflater.inflate(R.layout.onboard_lock_fragment, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        initView(view)
    }

    override fun onResume() {
        super.onResume()
        (baseActivity as OnBoardActivityInterface).enableSwipe(
            isSwipeable = true, isTabLayoutVisible = true
        )
        (baseActivity as OnBoardActivityInterface).showButtons(
            isNextButtonVisible = false, isBackButtonVisible = true
        )
    }

    override fun initView(view: View) {
        arguments?.let { isFromSettings = it.getBoolean(IS_FROM_SETTINGS, false) }
        lockPasswordBtn = view.findViewById(R.id.lockPasswordBtn)
        lockPINdBtn = view.findViewById(R.id.lockPINdBtn)
        lockPatternBtn = view.findViewById(R.id.lockPatternBtn)
        cancelBtn = view.findViewById(R.id.cancelBtn)

        // Phase 6.1.16 — V2 has a single lock method (PIN). Hide the legacy
        // Tella pattern/password options; the remaining button bridges into
        // the V2 identity-setup chain.
        lockPasswordBtn.visibility = View.GONE
        lockPatternBtn.visibility = View.GONE
        lockPINdBtn.isChecked = true

        if (isFromSettings) {
            cancelBtn.visibility = View.VISIBLE
            (baseActivity as OnBoardingActivity).hideViewpager()
        }
        initListeners()
    }

    private fun initListeners() {
        lockPINdBtn.setOnClickListener {
            goToIdentitySetup()
        }
        cancelBtn.setOnClickListener {
            (baseActivity as OnBoardActivityInterface).setCurrentIndicator(2)
            baseActivity.onBackPressed()
        }
    }

    private fun goToIdentitySetup() {
        (baseActivity as OnBoardingActivity).hideViewpager()
        // 10.6 / onboarding crash fix (2026-06-13) — plain 2-arg add (no hide,
        // no animation), mirroring OnBoardingActivity.goToIdentitySetup(). Same
        // SpecialEffectsController null-view NPE (androidx.fragment 1.3.0-rc01)
        // as the OnBoardLockSetFragment re-enroll path: this fragment is added
        // standalone (replaceFragmentNoAddToBackStack, isFromSettings), so the
        // animated hide + add of the mnemonic fragment crashes.
        baseActivity.addFragment(OnBoardMnemonicGenerateFragment(), R.id.rootOnboard)
    }
}
