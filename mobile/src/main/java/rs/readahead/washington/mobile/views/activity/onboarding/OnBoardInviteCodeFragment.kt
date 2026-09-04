package rs.readahead.washington.mobile.views.activity.onboarding

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import org.stream.crypto.StreamPreferences
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.views.base_ui.BaseFragment

class OnBoardInviteCodeFragment : BaseFragment() {

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_onboard_invite_code, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        initView(view)
    }

    override fun initView(view: View) {
        (baseActivity as OnBoardActivityInterface).hideProgress()

        val inviteInput = view.findViewById<EditText>(R.id.inviteCodeInput)

        view.findViewById<TextView>(R.id.validateBtn).setOnClickListener {
            val code = inviteInput.text.toString().trim()
            if (code.isNotEmpty()) {
                StreamPreferences.saveInviteCode(requireContext(), code)
            }
            navigateToAllDone()
        }

        view.findViewById<TextView>(R.id.skipBtn).setOnClickListener {
            navigateToAllDone()
        }

        view.findViewById<TextView>(R.id.backBtn).setOnClickListener {
            baseActivity.onBackPressed()
        }
    }

    private fun navigateToAllDone() {
        baseActivity.addFragment(this, OnBoardAllDoneFragment(), R.id.rootOnboard)
    }
}
