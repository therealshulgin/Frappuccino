package rs.readahead.washington.mobile.views.activity.onboarding

interface OnBoardActivityInterface {
    fun setCurrentIndicator(index: Int)
    fun hideProgress()
    fun showProgress()
    fun initProgress(itemCount: Int)
    fun initViewPager(itemCount: Int)
    fun enableSwipe(isSwipeable: Boolean, isTabLayoutVisible: Boolean)
    fun showButtons(isNextButtonVisible: Boolean, isBackButtonVisible: Boolean)
    fun hideViewpager()
}
