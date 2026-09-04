package org.hzontal.shared_ui.pinview

import android.content.Context
import android.graphics.drawable.Drawable
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.View
import android.view.animation.OvershootInterpolator
import android.widget.ImageView
import android.widget.RelativeLayout
import android.widget.TextView
import androidx.constraintlayout.widget.Group
import org.hzontal.shared_ui.R

/**
 * Represents a numeric lock view which can used to taken numbers as input.
 * The length of the input can be customized using [PinLockView.setMinPinLength] (int)}, the default value being 6
 *
 *
 * It can also be used as dial pad for taking number inputs.
 */
class PinLockView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : RelativeLayout(context, attrs, defStyleAttr), PinViewListener {
    var minPinLength = 0
    private var mHorizontalSpacing = 0
    private var mVerticalSpacing = 0
    private var mTextColor = 0
    private var mDeleteButtonPressedColor = 0
    private var mOffTextColor = 0
    private var mTextSize = 0
    private var mButtonSize = 0
    private var mDeleteButtonSize = 0
    private var mButtonBackgroundDrawable: Drawable? = null
    private var mDeleteButtonDrawable: Drawable? = null
    private var mShowDeleteButton = false
    private var mPinLockListener: PinLockListener? = null
    private var mCustomizationOptionsBundle: CustomizationOptionsBundle? = null
    private lateinit var mGroupButtons : Group
    private lateinit var mOnKeyBoardClickListener : OnKeyBoardClickListener
    private lateinit var mOkButton : TextView
    companion object {
        const val DEFAULT_PIN_LENGTH = 6
        private val DEFAULT_KEY_SET = intArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 0)
    }

    init {
        LayoutInflater.from(context).inflate(R.layout.keyboard_view, this, true)
        initView()
        init(attrs, defStyleAttr)
    }

    private fun init(attributeSet: AttributeSet?, defStyle: Int) {
        val typedArray = context.obtainStyledAttributes(attributeSet, R.styleable.PinLockView)
        try {
            minPinLength = typedArray.getInt(R.styleable.PinLockView_pinLength, DEFAULT_PIN_LENGTH)
            mHorizontalSpacing = typedArray.getDimension(R.styleable.PinLockView_keypadHorizontalSpacing, ResourceUtils.getDimensionInPx(context, R.dimen.default_horizontal_spacing)).toInt()
            mVerticalSpacing = typedArray.getDimension(R.styleable.PinLockView_keypadVerticalSpacing, ResourceUtils.getDimensionInPx(context, R.dimen.default_vertical_spacing)).toInt()
            mTextColor = typedArray.getColor(R.styleable.PinLockView_keypadTextColor, ResourceUtils.getColor(context, R.color.wa_white))
            mOffTextColor = typedArray.getColor(R.styleable.PinLockView_keypadOffTextColor, ResourceUtils.getColor(context, R.color.wa_white_40))
            mTextSize = typedArray.getDimension(R.styleable.PinLockView_keypadTextSize, ResourceUtils.getDimensionInPx(context, R.dimen.default_text_size)).toInt()
            mButtonSize = typedArray.getDimension(R.styleable.PinLockView_keypadButtonSize, ResourceUtils.getDimensionInPx(context, R.dimen.default_button_size)).toInt()
            mDeleteButtonSize = typedArray.getDimension(R.styleable.PinLockView_keypadDeleteButtonSize, ResourceUtils.getDimensionInPx(context, R.dimen.default_delete_button_size)).toInt()
            mButtonBackgroundDrawable = typedArray.getDrawable(R.styleable.PinLockView_keypadButtonBackgroundDrawable)
            mDeleteButtonDrawable = typedArray.getDrawable(R.styleable.PinLockView_keypadDeleteButtonDrawable)
            mShowDeleteButton = typedArray.getBoolean(R.styleable.PinLockView_keypadShowDeleteButton, true)
            mDeleteButtonPressedColor = typedArray.getColor(R.styleable.PinLockView_keypadDeleteButtonPressedColor, ResourceUtils.getColor(context, R.color.tigers_eye))
        } finally {
            typedArray.recycle()
        }
        mCustomizationOptionsBundle = CustomizationOptionsBundle()
        mCustomizationOptionsBundle!!.textColor = mTextColor
        mCustomizationOptionsBundle!!.seOffTextColor(mOffTextColor)
        mCustomizationOptionsBundle!!.textSize = mTextSize
        mCustomizationOptionsBundle!!.buttonSize = mButtonSize
        mCustomizationOptionsBundle!!.buttonBackgroundDrawable = mButtonBackgroundDrawable
        mCustomizationOptionsBundle!!.deleteButtonDrawable = mDeleteButtonDrawable
        mCustomizationOptionsBundle!!.deleteButtonSize = mDeleteButtonSize
        mCustomizationOptionsBundle!!.isShowDeleteButton = mShowDeleteButton
        mCustomizationOptionsBundle!!.deleteButtonPressesColor = mDeleteButtonPressedColor
        initView()
    }

    private fun initView() {
        mGroupButtons = findViewById(R.id.btnsGroup)
        mOkButton = findViewById(R.id.okBtn)
    }

    /**
     * Sets a [PinLockListener] to the to listen to pin update events
     *
     * @param pinLockListener the listener
     */
    fun setPinLockListener(pinLockListener: PinLockListener?) {
        mPinLockListener = pinLockListener
        mOnKeyBoardClickListener = OnKeyBoardClickListener(minPinLength,pinLockListener,this)
        initListeners()
    }


    /**
     * init buttons listener
     */

    private fun initListeners () {
        mGroupButtons.referencedIds.forEach {
            val button = findViewById<TextView>(it)
            button.setOnClickListener { v ->
                bump(v)
                mOnKeyBoardClickListener.onClick(v)
            }
        }
       val deleteButton = findViewById<ImageView>(R.id.deleteBtn)
        deleteButton.setOnClickListener { v ->
            bump(v)
            mOnKeyBoardClickListener.onClick(v)
        }
        deleteButton.contentDescription = context.getString(R.string.action_delete)
    }

    /**
     * Frappuccino (Phase 7.2 bonus) — tactile + visual feedback on each key
     * tap so the user gets a clear "bump" confirming the press registered.
     * Haptic = a short keyboard-tap tick; FLAG_IGNORE_VIEW_SETTING fires it
     * even where the per-view haptic flag defaults off, while still
     * respecting the user's GLOBAL haptic setting. Visual = a quick
     * scale-down then an overshoot spring back to 1.0 (a small "pop").
     */
    private fun bump(v: View) {
        // Drive the keypress haptic with an explicit Vibrator tick on every PIN
        // screen, not with View.performHapticFeedback. Two OnePlus/OxygenOS
        // quirks, confirmed on device (sdk 36, 2026-06-18), make the standard API
        // unusable on the PIN *unlock* screen, which is a FLAG_SECURE window: the
        // KEYBOARD_TAP window haptic is silently dropped there even though
        // performHapticFeedback returns true, and Settings.HAPTIC_FEEDBACK_ENABLED
        // reads 0 while haptics are actually ON. A direct Vibrator isn't gated by
        // the window flag, and we deliberately don't gate on that unreliable
        // setting — matching StreamActivity's existing unconditional shake
        // vibrate. Best-effort: never crashes a key press.
        vibrateKeyTick()
        v.animate().cancel()
        v.scaleX = 0.9f
        v.scaleY = 0.9f
        v.animate()
            .scaleX(1f).scaleY(1f)
            .setDuration(130L)
            .setInterpolator(OvershootInterpolator())
            .start()
    }

    /**
     * Explicit keypress haptic (see [bump]). Uniform across all PIN screens and
     * unaffected by FLAG_SECURE — verified on-device (OnePlus 13 / OxygenOS,
     * sdk 36, 2026-06-18 via `dumpsys vibrator_manager`): a direct Vibrator goes
     * through VibratorManagerService regardless of the window flag, whereas
     * View.performHapticFeedback(KEYBOARD_TAP) is silently dropped on a
     * FLAG_SECURE window by OxygenOS.
     *
     * EFFECT_TICK *fired* (HAL logged TICK STRONG finished) but is the lightest
     * predefined effect — imperceptible on this LRA when tapping. We use a
     * stronger predefined effect (EFFECT_HEAVY_CLICK, present in the device's
     * supportedEffects) on API 29+, an explicit ~35 ms one-shot on API 26-28,
     * and a legacy 35 ms pulse below — mirroring the explicit-duration vibrate()
     * that already works in StreamActivity. USAGE_TOUCH (API 33+) is declared so
     * the OS classifies this as touch feedback (not USAGE_UNKNOWN) and never
     * reclassifies/attenuates it under OEM haptic policies. Deliberately NOT
     * gated on HAPTIC_FEEDBACK_ENABLED (reads 0 on OxygenOS while haptics are
     * on). Best-effort: never crashes a key press.
     */
    @Suppress("DEPRECATION")
    private fun vibrateKeyTick() {
        try {
            val vibrator = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                (context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE)
                    as? android.os.VibratorManager)?.defaultVibrator
            } else {
                context.getSystemService(Context.VIBRATOR_SERVICE) as? android.os.Vibrator
            } ?: return
            if (!vibrator.hasVibrator()) return

            val sdk = android.os.Build.VERSION.SDK_INT
            val effect: android.os.VibrationEffect? = when {
                sdk >= android.os.Build.VERSION_CODES.Q ->
                    android.os.VibrationEffect.createPredefined(
                        android.os.VibrationEffect.EFFECT_HEAVY_CLICK
                    )
                sdk >= android.os.Build.VERSION_CODES.O ->
                    android.os.VibrationEffect.createOneShot(
                        35L, android.os.VibrationEffect.DEFAULT_AMPLITUDE
                    )
                else -> null // legacy path below
            }

            when {
                sdk >= android.os.Build.VERSION_CODES.TIRAMISU && effect != null -> {
                    val attrs = android.os.VibrationAttributes.Builder()
                        .setUsage(android.os.VibrationAttributes.USAGE_TOUCH)
                        .build()
                    vibrator.vibrate(effect, attrs)
                }
                effect != null -> vibrator.vibrate(effect)
                else -> vibrator.vibrate(35L)
            }
        } catch (e: Exception) {
            // Best-effort feedback only; never let it break a key press.
        }
    }


    override fun onHiLightView(pin: String) {
        if (pin.length >= DEFAULT_PIN_LENGTH) {
            mOkButton.setTextColor(mCustomizationOptionsBundle!!.textColor)
        } else {
            mOkButton.setTextColor(mCustomizationOptionsBundle!!.offTextColor)
        }
    }


}