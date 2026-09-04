package rs.readahead.washington.mobile.views.activity.onboarding

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.databinding.OnboardLockSetFragmentBinding
import rs.readahead.washington.mobile.util.hide
import rs.readahead.washington.mobile.views.base_ui.BaseFragment

class OnBoardLockSetFragment : BaseFragment() {

    private lateinit var binding: OnboardLockSetFragmentBinding
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        binding = OnboardLockSetFragmentBinding.inflate(layoutInflater)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        initView(view)
    }

    override fun initView(view: View) {
        (baseActivity as OnBoardActivityInterface).setCurrentIndicator(3)
        (baseActivity as OnBoardingActivity).hideViewpager()
        (baseActivity as OnBoardingActivity).showProgress()
        with(binding) {
            nextBtn.setOnClickListener {
                // Enter the V2 identity-setup chain with the PLAIN 2-arg add:
                // no hide, no setCustomAnimations. Do not "harmonize" this
                // with the animated 3-arg addFragment(hide + add) used
                // elsewhere in the app — it trips a null-view NPE in
                // androidx.fragment 1.3.0-rc01's SpecialEffectsController when
                // the fragment being hidden was added standalone via
                // replaceFragmentNoAddToBackStack, which is exactly this
                // post-wipe / re-enroll entry (10.6, onboarding crash fix).
                //
                // The missing transition costs nothing: the mnemonic-generate
                // screen is opaque (wa_purple) so it fully covers this one,
                // and back still works since the 2-arg add uses addToBackStack.
                // Same call shape as OnBoardingActivity.goToIdentitySetup()
                // for first-run onboarding.
                baseActivity.addFragment(
                    OnBoardMnemonicGenerateFragment(),
                    R.id.rootOnboard
                )
            }
            backBtn.hide()
        }
    }
}