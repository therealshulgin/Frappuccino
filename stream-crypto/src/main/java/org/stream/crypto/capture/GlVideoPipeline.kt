package org.stream.crypto.capture

import android.graphics.SurfaceTexture
import android.opengl.EGL14
import android.opengl.EGLConfig
import android.opengl.EGLContext
import android.opengl.EGLDisplay
import android.opengl.EGLExt
import android.opengl.EGLSurface
import android.opengl.GLES11Ext
import android.opengl.GLES20
import android.opengl.Matrix
import android.os.Handler
import android.os.HandlerThread
import android.view.Surface
import timber.log.Timber
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.FloatBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * OpenGL wedge between the camera and the MediaCodec input Surface.
 *
 * Never hand a `MediaCodec.createInputSurface()` Surface to the camera as an
 * output. The strict Mediatek HAL on the Seeker rejects it outright
 * (`endConfigure: Unsupported set of inputs/outputs provided`) : that Surface
 * carries a BufferQueue usage-flag combination the HAL refuses. That was the H1
 * prototype, which fed it straight to CameraX `Preview.SurfaceProvider`, and it
 * is the reason this class exists.
 *
 * So the camera only ever sees a [SurfaceTexture] here — the standard
 * `IMPLEMENTATION_DEFINED` format that all OEM HALs accept — and we render from
 * it into the encoder Surface ourselves :
 *
 *     Camera → SurfaceTexture → external OES texture → fullscreen quad
 *            → MediaCodec input Surface (written from GL, not from the camera)
 *
 * The encoder Surface is then wired to our EGL context and never to the HAL, so
 * HAL strictness is out of the picture. Interposing a GL step this way is what
 * Snapchat, OBS Mobile, Larix Broadcaster and Telegram do — it is not a local
 * hack. It also gives us back the choice of the codec mime type and a real
 * bitrate, which CameraX only takes as a soft hint.
 *
 * All EGL and GL calls run on one dedicated thread ([HandlerThread]
 * "GlVideoPipeline") : an EGL context is bound to a single thread at a time and
 * touching it from anywhere else causes EGL_BAD_CONTEXT. The public API is safe
 * to call from any thread because it goes through that Handler.
 *
 * Usage : construct with the first encoder Surface, call [start] — it blocks
 * until the EGL thread, the GL program, the OES texture and the SurfaceTexture
 * are ready — then hand [cameraSurfaceTexture] to CameraX. Frames flow on their
 * own from there : every frame-available callback draws the OES texture onto the
 * encoder Surface. [stop] tears the EGL context down.
 *
 * Audio is not handled here : PcmCaptureThread and AacEncoderSession capture it
 * in parallel (H2-B.2) and ChunkEncoderBundle muxes it into the same MP4.
 *
 * @param initialOutputSurface the Surface obtained from
 *   `MediaCodec.createInputSurface()`. The pipeline owns the EGL window
 *   surface backed by this Surface; the caller must NOT touch it
 *   directly until [stop] returns. Swappable at runtime via
 *   [setOutputSurface] (chunk rotation + adaptive quality swap).
 * @param widthPx initial encoder render width — must match the MediaCodec
 *   encoder's configured width. Updated by [setOutputSurface] when an
 *   adaptive quality swap repoints the pipeline at a new-resolution encoder.
 * @param heightPx initial encoder render height — see [widthPx].
 */
class GlVideoPipeline(
    initialOutputSurface: Surface,
    widthPx: Int,
    heightPx: Int,
) {
    // Mutable so chunk rotation (Phase H2-B.4) can swap to a fresh
    // MediaCodec input Surface without tearing down the EGL context,
    // the GL program, the OES texture, or the camera-side
    // SurfaceTexture (all of which would force a camera unbind +
    // rebind otherwise).
    private var outputSurface: Surface = initialOutputSurface

    // Encoder-pass render dimensions, mutable alongside [outputSurface] so an
    // adaptive QUALITY swap can repoint the pipeline at a new-resolution encoder
    // Surface IN PLACE — same mechanism as a rotation, with new dims. Do not
    // "simplify" a quality change into a teardown + restart : the teardown runs
    // the forensic black-scrub and drops frames, which blacked out the on-screen
    // preview on every quality change (H2-B §Bugs #5), and it costs a camera
    // rebind on top. The preview pass is unaffected — it letterboxes to the
    // ENCODER aspect (widthPx:heightPx), a near-constant ~9:16 across all
    // qualities : 480×854 is 0.5621 against 0.5625 elsewhere, a sub-pixel
    // difference. Written and read on the GL thread only (in [setOutputSurface]
    // and the draw loop), so @Volatile here is defensive.
    @Volatile private var widthPx: Int = widthPx
    @Volatile private var heightPx: Int = heightPx

    private val thread = HandlerThread("GlVideoPipeline").apply { start() }
    private val handler = Handler(thread.looper)
    private val running = AtomicBoolean(false)

    // EGL14 state — only accessed from the GL thread.
    private var eglDisplay: EGLDisplay = EGL14.EGL_NO_DISPLAY
    private var eglContext: EGLContext = EGL14.EGL_NO_CONTEXT
    private var eglSurface: EGLSurface = EGL14.EGL_NO_SURFACE

    /**
     * 1×1 PBuffer kept as a safe binding target whenever the current window
     * surface (encoder or preview) has to be swapped or destroyed.
     *
     * It exists to avoid `eglMakeCurrent(... EGL_NO_SURFACE ...)` : some Adreno
     * (Snapdragon legacy) and Mali (Mediatek Helio) drivers leave the context in
     * a corrupted state after such a binding, and the next bind on a real
     * surface then fails with `EGL_BAD_MATCH` (Blue HIGH-4 audit).
     *
     * Created in [initEgl] right after the context, destroyed in stop() AFTER
     * all window surfaces are torn down. One 1×1 RGBA8 surface : negligible,
     * and nothing to optimise here.
     */
    private var eglPbufferSurface: EGLSurface = EGL14.EGL_NO_SURFACE
    private var eglConfig: EGLConfig? = null

    // Optional second EGL window surface
    // for on-screen preview. The EGL context is shared with [eglSurface]
    // (encoder target), so each camera frame is drawn twice : once onto
    // the encoder Surface (with frame-PTS for muxing) and once onto the
    // preview Surface (no PTS — display only). Null when no preview is
    // attached.
    private var eglPreviewSurface: EGLSurface = EGL14.EGL_NO_SURFACE
    private var previewOutputSurface: Surface? = null

    // Actual sensor buffer dimensions, plus the rotation CameraX requires to
    // bring that buffer to the target display orientation. Do not fold these
    // into widthPx / heightPx : on phones with a landscape-mounted sensor the
    // encoder dims are portrait while the buffer is landscape (encoder 720×1280,
    // sensor 1280×720), so taking the encoder dims as the source aspect computes
    // the wrong scale and gives a visible squash on landscape subjects. The two
    // pairs start out with the same values just below, which is what makes
    // merging them tempting.
    //
    // The MVP applied to the geometry is Scale(fit) only, computed against the
    // ROTATED source aspect — there is no rotation in it, see drawFullscreenQuad
    // — and [stMatrix] is sent untouched (just the OEM's Y-flip / crop).
    //
    // Written from the calling thread (CameraX's main executor, via
    // RollingChunkRecorder.setSourceTransform) and read on the GL thread, so
    // @Volatile is required here.
    @Volatile private var sourceWidthPx: Int = widthPx
    @Volatile private var sourceHeightPx: Int = heightPx
    @Volatile private var sourceRotationDegrees: Int = 0

    // GL program + attribute locations.
    private var program: Int = 0
    private var aPositionLoc: Int = -1
    private var aTexCoordLoc: Int = -1
    private var uMvpMatrixLoc: Int = -1
    private var uStMatrixLoc: Int = -1
    private var oesTextureId: Int = 0

    // Camera input.
    private var cameraSurfaceTextureInternal: SurfaceTexture? = null
    private val stMatrix = FloatArray(16)
    private val mvpMatrix = FloatArray(16).also { Matrix.setIdentityM(it, 0) }
    private val frameAvailableLatch = AtomicBoolean(false)

    // Diagnostic one-shot flag (cover-fit 2.05× follow-up, 2026-05-17).
    // True until the first preview draw logs its dimensions, then false.
    private val previewDimsLogged = AtomicBoolean(false)

    // Two more one-shot flags : log the effective GL viewport once for
    // the encoder pass and once for the preview pass. If the driver
    // clamped to a smaller back buffer, we'll see it here.
    private val encoderDrawDimsLogged = AtomicBoolean(false)
    private val previewDrawDimsLogged = AtomicBoolean(false)

    // Frame-rate diagnostic (2026-05-18) — accumulates per-frame timings
    // and logs a windowed summary every [FRAME_METRICS_WINDOW_NS]. Used
    // to investigate the rolling-mode FPS drop observed in B.4 (~13 fps
    // rolling vs 22 fps single-chunk). Counters live on the GL thread,
    // no synchronization needed.
    private var frMetricsWindowStartNs: Long = 0L
    private var frMetricsFrameCount: Int = 0
    private var frMetricsTotalDrawNs: Long = 0L
    private var frMetricsTotalEncoderSwapNs: Long = 0L
    private var frMetricsTotalPreviewSwapNs: Long = 0L
    private var frMetricsMaxFrameNs: Long = 0L
    private var frMetricsMaxEncoderSwapNs: Long = 0L
    private var frMetricsMaxPreviewSwapNs: Long = 0L

    /**
     * Returns the SurfaceTexture the caller should hand to the camera
     * (typically via `Surface(surfaceTexture)` + CameraX
     * `Preview.SurfaceProvider`). Available only after [start] returns
     * successfully.
     */
    fun cameraSurfaceTexture(): SurfaceTexture {
        return cameraSurfaceTextureInternal
            ?: error("start() must be called and complete before cameraSurfaceTexture()")
    }

    /**
     * Spins up the EGL thread, creates the GL program + OES texture +
     * SurfaceTexture. Blocks the calling thread until setup is done so
     * the returned SurfaceTexture is immediately usable.
     */
    fun start() {
        check(!running.getAndSet(true)) { "Already started" }
        val latch = CountDownLatch(1)
        handler.post {
            try {
                initEgl()
                initGlProgram()
                initOesTexture()
                Timber.tag("StreamMetrics").i(
                    "glPipelineStart w=%d h=%d", widthPx, heightPx
                )
            } catch (e: Exception) {
                Timber.e(e, "GL pipeline init failed")
            } finally {
                latch.countDown()
            }
        }
        latch.await()
    }

    /**
     * Tears down GL + EGL on the GL thread, then quits the thread.
     * Blocks until cleanup is complete.
     */
    fun stop() {
        if (!running.getAndSet(false)) return
        val latch = CountDownLatch(1)
        handler.post {
            try {
                cameraSurfaceTextureInternal?.release()
                cameraSurfaceTextureInternal = null
                if (oesTextureId != 0) {
                    val arr = intArrayOf(oesTextureId)
                    GLES20.glDeleteTextures(1, arr, 0)
                    oesTextureId = 0
                }
                if (program != 0) {
                    GLES20.glDeleteProgram(program)
                    program = 0
                }
                if (eglDisplay != EGL14.EGL_NO_DISPLAY) {
                    // Paint black and glFinish BEFORE destroying the EGL
                    // surfaces : the last rendered frame is plaintext sitting in
                    // our backbuffers, and a post-seizure VRAM or gralloc dump
                    // could recover it. glFinish is what forces the GPU to run
                    // the clears while the surfaces and the context still exist.
                    // Two asymmetries below look like mistakes and are not.
                    // Preview : clear and swap TWICE, to cycle the double buffer
                    // — with a single swap the surface on screen keeps showing
                    // the last image. Encoder input surface : clear WITHOUT
                    // swapping, because injecting a frame after EOS could corrupt
                    // the muxed MP4 ; we only scrub our current backbuffer. This
                    // reaches our own backbuffers and nothing more : what the
                    // encoder or SurfaceFlinger already consumed lives in their
                    // BufferQueues and is firmware-dependent (8.1.6-#3 /
                    // forensic #3, see FORENSIC_VALIDATION_PLAN surface 9). Each
                    // step is guarded so an already-released surface never breaks
                    // teardown.
                    runCatching {
                        if (eglPreviewSurface != EGL14.EGL_NO_SURFACE &&
                            EGL14.eglMakeCurrent(
                                eglDisplay, eglPreviewSurface, eglPreviewSurface, eglContext
                            )
                        ) {
                            GLES20.glClearColor(0f, 0f, 0f, 1f)
                            GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT)
                            EGL14.eglSwapBuffers(eglDisplay, eglPreviewSurface)
                            GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT)
                            EGL14.eglSwapBuffers(eglDisplay, eglPreviewSurface)
                        }
                    }.onFailure { Timber.w(it, "preview black-clear on teardown failed") }
                    runCatching {
                        if (eglSurface != EGL14.EGL_NO_SURFACE &&
                            EGL14.eglMakeCurrent(
                                eglDisplay, eglSurface, eglSurface, eglContext
                            )
                        ) {
                            GLES20.glClearColor(0f, 0f, 0f, 1f)
                            GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT)
                        }
                    }.onFailure { Timber.w(it, "encoder black-clear on teardown failed") }
                    runCatching { GLES20.glFinish() }
                    EGL14.eglMakeCurrent(
                        eglDisplay,
                        EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE,
                        EGL14.EGL_NO_CONTEXT
                    )
                    if (eglPreviewSurface != EGL14.EGL_NO_SURFACE) {
                        EGL14.eglDestroySurface(eglDisplay, eglPreviewSurface)
                        eglPreviewSurface = EGL14.EGL_NO_SURFACE
                    }
                    previewOutputSurface = null
                    if (eglSurface != EGL14.EGL_NO_SURFACE) {
                        EGL14.eglDestroySurface(eglDisplay, eglSurface)
                        eglSurface = EGL14.EGL_NO_SURFACE
                    }
                    // Destroy the PBuffer fallback. Done
                    // AFTER both window surfaces are torn down (so we
                    // never need it again) but BEFORE context destroy
                    // (per EGL spec, surfaces must be destroyed before
                    // their context).
                    if (eglPbufferSurface != EGL14.EGL_NO_SURFACE) {
                        EGL14.eglDestroySurface(eglDisplay, eglPbufferSurface)
                        eglPbufferSurface = EGL14.EGL_NO_SURFACE
                    }
                    if (eglContext != EGL14.EGL_NO_CONTEXT) {
                        EGL14.eglDestroyContext(eglDisplay, eglContext)
                        eglContext = EGL14.EGL_NO_CONTEXT
                    }
                    EGL14.eglReleaseThread()
                    EGL14.eglTerminate(eglDisplay)
                    eglDisplay = EGL14.EGL_NO_DISPLAY
                }
                Timber.tag("StreamMetrics").i("glPipelineStop done")
            } catch (e: Exception) {
                Timber.w(e, "GL teardown threw")
            } finally {
                latch.countDown()
            }
        }
        // #8/MOTTO: bound the teardown await too. A wedged GL thread (the very
        // premise of #8 — a hang in drawFrameIfRunning's eglSwapBuffers) must not
        // hang stop() forever: recorder.stop() calls this BEFORE finalizing the
        // current chunk, so an unbounded hang here would strand the last chunk in
        // the clear (then purgeOrphanChunks would secure-delete it). On timeout,
        // abandon the wedged thread (quitSafely won't unstick a native hang, but
        // the process continues and the caller finalizes + encrypts the chunk).
        if (!latch.await(GL_OP_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            Timber.e(
                "GlVideoPipeline.stop timed out after %dms — abandoning wedged GL thread",
                GL_OP_TIMEOUT_MS
            )
        }
        thread.quitSafely()
    }

    // -------------------- GL thread helpers --------------------

    private fun initEgl() {
        eglDisplay = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY)
        check(eglDisplay != EGL14.EGL_NO_DISPLAY) { "eglGetDisplay failed" }
        val version = IntArray(2)
        check(EGL14.eglInitialize(eglDisplay, version, 0, version, 1)) {
            "eglInitialize failed"
        }

        // Recordable Android EGL config — the EGL_RECORDABLE_ANDROID
        // attribute (0x3142) ensures the chosen config produces buffers
        // that MediaCodec accepts as input. Without this, some devices
        // produce green/black frames after encoding.
        val attribList = intArrayOf(
            EGL14.EGL_RED_SIZE, 8,
            EGL14.EGL_GREEN_SIZE, 8,
            EGL14.EGL_BLUE_SIZE, 8,
            EGL14.EGL_ALPHA_SIZE, 8,
            EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
            EGL_RECORDABLE_ANDROID, 1,
            EGL14.EGL_NONE
        )
        val configs = arrayOfNulls<EGLConfig>(1)
        val numConfigs = IntArray(1)
        check(EGL14.eglChooseConfig(eglDisplay, attribList, 0, configs, 0, 1, numConfigs, 0)
            && numConfigs[0] > 0
        ) { "eglChooseConfig failed" }
        val config = configs[0] ?: error("no EGL config")
        eglConfig = config

        val ctxAttribs = intArrayOf(
            EGL14.EGL_CONTEXT_CLIENT_VERSION, 2,
            EGL14.EGL_NONE
        )
        eglContext = EGL14.eglCreateContext(
            eglDisplay, config, EGL14.EGL_NO_CONTEXT, ctxAttribs, 0
        )
        check(eglContext != EGL14.EGL_NO_CONTEXT) { "eglCreateContext failed" }

        // 1×1 PBuffer fallback. Created BEFORE the
        // window surface so it's always available as a re-bind target
        // when we have to destroy or swap the encoder/preview surface.
        // Blue HIGH-4 : avoids the EGL_NO_SURFACE detour that Adreno/
        // Mali drivers handle poorly.
        val pbufferAttribs = intArrayOf(
            EGL14.EGL_WIDTH, 1,
            EGL14.EGL_HEIGHT, 1,
            EGL14.EGL_NONE,
        )
        eglPbufferSurface = EGL14.eglCreatePbufferSurface(
            eglDisplay, config, pbufferAttribs, 0
        )
        check(eglPbufferSurface != EGL14.EGL_NO_SURFACE) {
            "eglCreatePbufferSurface failed: 0x${EGL14.eglGetError().toString(16)}"
        }

        val surfaceAttribs = intArrayOf(EGL14.EGL_NONE)
        eglSurface = EGL14.eglCreateWindowSurface(
            eglDisplay, config, outputSurface, surfaceAttribs, 0
        )
        check(eglSurface != EGL14.EGL_NO_SURFACE) { "eglCreateWindowSurface failed" }

        check(EGL14.eglMakeCurrent(eglDisplay, eglSurface, eglSurface, eglContext)) {
            "eglMakeCurrent failed"
        }
    }

    /**
     * Declares the REAL sensor buffer dimensions, as delivered by CameraX, and
     * the rotation in degrees CCW that CameraX reports in TransformationInfo to
     * bring that buffer to the target display orientation.
     *
     * Both conventions matter and neither raises an error when it is wrong :
     * passing the encoder dimensions here, or a rotation taken the other way
     * round, silently yields a squashed or rotated recording — a bug only
     * noticed when the video is played back.
     *
     * Typical : CameraX hands us a 1280×720 landscape buffer for a portrait
     * phone with the rear camera mounted at 90°, so the call is
     * `setSourceTransform(1280, 720, 90)`. The encoder viewport stays 720×1280
     * portrait. The pipeline uses the rotation only to pick the rotated source
     * dims for its fit — the MVP is Scale(fit) alone, with no rotation in it,
     * and the texture sampling (stMatrix) is left untouched. The fit itself is
     * then exact (same aspect after rotation) ; the derived vertical anamorphic
     * correction is applied on top of it, so the final geometry is deliberately
     * not the identity (see drawFullscreenQuad).
     */
    fun setSourceTransform(bufferWidthPx: Int, bufferHeightPx: Int, rotationDegrees: Int) {
        sourceWidthPx = bufferWidthPx
        sourceHeightPx = bufferHeightPx
        sourceRotationDegrees = rotationDegrees
    }

    /**
     * Attaches — or, with `null`, detaches — a second EGL window surface used as
     * the on-screen preview. Each camera frame is then drawn twice from the same
     * OES texture : once onto the encoder Surface with a PTS for muxing, once
     * onto this one with no PTS, display only. The muxed timeline is anchored by
     * the encoder pass alone — the `eglPresentationTimeANDROID` call in
     * drawFrameIfRunning, on the encoder surface.
     *
     * The second draw costs a few hundred microseconds of GPU work because the
     * EGL context is shared. It is not a second camera output and no HAL
     * strictness is involved. Drawing the preview here rather than from a
     * separate CameraX use case is also what buys the WYSIWYG framing : the same
     * texture goes through the same fit, crop and vertical correction as the
     * recording, so the screen shows the frame that is being recorded (see the
     * WYSIWYG block in drawFrameIfRunning).
     *
     * Blocks the calling thread until the attachment is applied on the GL thread
     * so the orchestrator can deterministically sequence this with
     * [setOutputSurface] swaps, but only up to GL_OP_TIMEOUT_MS. Past that we
     * stop WAITING and log : the posted attach is not cancelled and may still
     * complete afterwards, so do not release the Surface on that path. The
     * preview is not recorded content, hence a log rather than a throw.
     *
     * Passing a new Surface while one is attached destroys the old preview
     * EGLSurface and creates a new one. Idempotent : passing the same Surface
     * twice is a no-op.
     */
    fun setPreviewOutputSurface(surface: Surface?) {
        check(running.get()) { "setPreviewOutputSurface called before start() or after stop()" }
        val latch = CountDownLatch(1)
        handler.post {
            try {
                if (surface === previewOutputSurface) {
                    return@post
                }
                val display = eglDisplay
                val context = eglContext
                if (display == EGL14.EGL_NO_DISPLAY || context == EGL14.EGL_NO_CONTEXT) {
                    Timber.w("setPreviewOutputSurface : EGL not ready, skipping")
                    return@post
                }
                // Destroy the old preview surface, if any. Bind the context to
                // another surface first — the old one may be the surface
                // currently bound. Never bind to EGL_NO_SURFACE for that : some
                // Adreno/Mali drivers leave the context in a corrupted state
                // after an EGL_NO_SURFACE binding, then fail subsequent
                // eglMakeCurrent(realSurface) with EGL_BAD_MATCH (Blue HIGH-4).
                // The encoder surface is the target of choice, the 1×1 PBuffer
                // the fallback when it isn't available.
                if (eglPreviewSurface != EGL14.EGL_NO_SURFACE) {
                    val rebindTarget = if (eglSurface != EGL14.EGL_NO_SURFACE) {
                        eglSurface
                    } else {
                        eglPbufferSurface
                    }
                    EGL14.eglMakeCurrent(display, rebindTarget, rebindTarget, context)
                    EGL14.eglDestroySurface(display, eglPreviewSurface)
                    eglPreviewSurface = EGL14.EGL_NO_SURFACE
                }
                previewOutputSurface = surface
                if (surface != null) {
                    val config = eglConfig ?: run {
                        Timber.w("setPreviewOutputSurface : eglConfig null, skipping create")
                        return@post
                    }
                    val attribs = intArrayOf(EGL14.EGL_NONE)
                    eglPreviewSurface = EGL14.eglCreateWindowSurface(
                        display, config, surface, attribs, 0
                    )
                    if (eglPreviewSurface == EGL14.EGL_NO_SURFACE) {
                        Timber.w(
                            "eglCreateWindowSurface (preview) failed: 0x%x",
                            EGL14.eglGetError()
                        )
                    }
                }
                Timber.tag("StreamMetrics").i(
                    "glPipelinePreviewSurface attached=%b", surface != null
                )
            } catch (e: Exception) {
                Timber.e(e, "setPreviewOutputSurface failed")
            } finally {
                latch.countDown()
            }
        }
        // #8: bounded await. Preview is not recorded content (non-motto), so a
        // stalled GL thread here is logged rather than thrown — it must neither
        // ANR the caller nor stop the encoder pipeline.
        if (!latch.await(GL_OP_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            Timber.e("setPreviewOutputSurface timed out after %dms — GL thread stalled", GL_OP_TIMEOUT_MS)
        }
    }

    /**
     * Repoints the pipeline at a new MediaCodec input Surface. The EGL context,
     * the GL program, the OES texture and the camera-side SurfaceTexture all
     * survive — only the destination buffer changes, in 1-5 ms on the GL thread
     * — which is why the camera never has to be unbound and rebound.
     *
     * The next frame coming out of the camera SurfaceTexture lands on
     * [newSurface]. The previous Surface is no longer referenced by this
     * pipeline : draining it and releasing its owning encoder is the
     * orchestrator's job, and skipping that drain loses the tail of the chunk.
     *
     * [newWidthPx]/[newHeightPx] update the encoder-pass viewport so the SAME
     * call also handles an adaptive QUALITY swap (new-resolution encoder), not
     * just a same-dims rotation — that is what lets a quality change reuse this
     * in-place swap instead of a full pipeline teardown + camera rebind (H2-B
     * §Bugs #5). Pass the current dims for a plain rotation.
     *
     * Blocks the calling thread until the swap is complete so the orchestrator
     * can sequence it deterministically with the encoder's
     * `signalEndOfInputStream()` on the old Surface.
     *
     * @throws GlPipelineStalledException if the GL thread hasn't answered within
     *   GL_OP_TIMEOUT_MS. An EGL failure caught on the GL thread is rethrown
     *   here too. Route to recovery in both cases, but they do not say the same
     *   thing. On an EGL failure the swap did not complete, and the state can be
     *   partial : the old EGL surface is already destroyed, and a new one may
     *   have been created without [widthPx]/[heightPx] following. On a timeout
     *   the outcome is simply UNKNOWN — the posted swap is never cancelled, so a
     *   merely slow GL thread can finish it after the throw. Do not release
     *   `newSurface` on that path : the pipeline may end up drawing on it.
     */
    fun setOutputSurface(newSurface: Surface, newWidthPx: Int, newHeightPx: Int) {
        check(running.get()) { "setOutputSurface called before start() or after stop()" }
        val latch = CountDownLatch(1)
        val errRef = AtomicReference<Exception?>(null)
        handler.post {
            try {
                if (eglDisplay == EGL14.EGL_NO_DISPLAY || eglContext == EGL14.EGL_NO_CONTEXT) {
                    // #3: surface as a failure (not a silent false-success) so the
                    // caller routes to recovery. Unreachable while running() (EGL
                    // lives start..stop), but keeps the #3 contract honest — the
                    // output surface was NOT repointed, so the swap did not happen.
                    Timber.w("setOutputSurface : EGL not ready")
                    errRef.set(IllegalStateException("setOutputSurface: EGL not ready"))
                    return@post
                }
                val config = eglConfig ?: run {
                    Timber.w("setOutputSurface : eglConfig null")
                    errRef.set(IllegalStateException("setOutputSurface: eglConfig null"))
                    return@post
                }
                // Detach the current surface from the context so we can
                // destroy it safely. Phase H2-B.12 (Blue HIGH-4) — bind
                // to the 1×1 PBuffer rather than EGL_NO_SURFACE so the
                // following eglCreateWindowSurface + eglMakeCurrent on
                // the new surface doesn't hit EGL_BAD_MATCH on
                // Adreno/Mali. If the PBuffer creation failed at init
                // (edge-case), fall back to the historic EGL_NO_SURFACE
                // path rather than crashing the swap.
                val detachTarget = if (eglPbufferSurface != EGL14.EGL_NO_SURFACE) {
                    eglPbufferSurface
                } else {
                    EGL14.EGL_NO_SURFACE
                }
                EGL14.eglMakeCurrent(
                    eglDisplay,
                    detachTarget, detachTarget,
                    eglContext
                )
                if (eglSurface != EGL14.EGL_NO_SURFACE) {
                    EGL14.eglDestroySurface(eglDisplay, eglSurface)
                    eglSurface = EGL14.EGL_NO_SURFACE
                }
                // Create + bind the new window surface.
                val surfaceAttribs = intArrayOf(EGL14.EGL_NONE)
                eglSurface = EGL14.eglCreateWindowSurface(
                    eglDisplay, config, newSurface, surfaceAttribs, 0
                )
                check(eglSurface != EGL14.EGL_NO_SURFACE) {
                    "eglCreateWindowSurface (rotate) failed: 0x${EGL14.eglGetError().toString(16)}"
                }
                check(EGL14.eglMakeCurrent(eglDisplay, eglSurface, eglSurface, eglContext)) {
                    "eglMakeCurrent (rotate) failed: 0x${EGL14.eglGetError().toString(16)}"
                }
                outputSurface = newSurface
                widthPx = newWidthPx
                heightPx = newHeightPx
                Timber.tag("StreamMetrics").i(
                    "glPipelineSwapSurface ok w=%d h=%d", newWidthPx, newHeightPx
                )
            } catch (e: Exception) {
                // #3: capture the EGL swap failure instead of swallowing it. A
                // swallowed failure left eglSurface == EGL_NO_SURFACE, so the
                // encoder pass silently stopped receiving frames — the video was
                // lost with the operator none the wiser (the worst motto case).
                Timber.e(e, "setOutputSurface failed")
                errRef.set(e)
            } finally {
                latch.countDown()
            }
        }
        // #8: bounded await — a wedged GL thread (shared with onFrameAvailable →
        // drawFrameIfRunning) must not freeze the rotation cadence forever.
        if (!latch.await(GL_OP_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            throw GlPipelineStalledException(
                "setOutputSurface timed out after ${GL_OP_TIMEOUT_MS}ms — GL thread stalled"
            )
        }
        // #3: re-throw on the caller thread so rotateChunk/swapVideoConfig route
        // it to their error path (recovery), not a silent dead-video session.
        errRef.get()?.let { throw it }
    }

    private fun initGlProgram() {
        val vertex = """
            uniform mat4 uMVPMatrix;
            uniform mat4 uSTMatrix;
            attribute vec4 aPosition;
            attribute vec4 aTexCoord;
            varying vec2 vTexCoord;
            void main() {
                gl_Position = uMVPMatrix * aPosition;
                vTexCoord = (uSTMatrix * aTexCoord).xy;
            }
        """.trimIndent()
        val fragment = """
            #extension GL_OES_EGL_image_external : require
            precision mediump float;
            varying vec2 vTexCoord;
            uniform samplerExternalOES sTexture;
            void main() {
                gl_FragColor = texture2D(sTexture, vTexCoord);
            }
        """.trimIndent()
        program = createProgram(vertex, fragment)
        aPositionLoc = GLES20.glGetAttribLocation(program, "aPosition")
        aTexCoordLoc = GLES20.glGetAttribLocation(program, "aTexCoord")
        uMvpMatrixLoc = GLES20.glGetUniformLocation(program, "uMVPMatrix")
        uStMatrixLoc = GLES20.glGetUniformLocation(program, "uSTMatrix")
    }

    private fun initOesTexture() {
        val textures = IntArray(1)
        GLES20.glGenTextures(1, textures, 0)
        oesTextureId = textures[0]
        GLES20.glBindTexture(GLES11Ext.GL_TEXTURE_EXTERNAL_OES, oesTextureId)
        GLES20.glTexParameteri(GLES11Ext.GL_TEXTURE_EXTERNAL_OES,
            GLES20.GL_TEXTURE_MIN_FILTER, GLES20.GL_LINEAR)
        GLES20.glTexParameteri(GLES11Ext.GL_TEXTURE_EXTERNAL_OES,
            GLES20.GL_TEXTURE_MAG_FILTER, GLES20.GL_LINEAR)
        GLES20.glTexParameteri(GLES11Ext.GL_TEXTURE_EXTERNAL_OES,
            GLES20.GL_TEXTURE_WRAP_S, GLES20.GL_CLAMP_TO_EDGE)
        GLES20.glTexParameteri(GLES11Ext.GL_TEXTURE_EXTERNAL_OES,
            GLES20.GL_TEXTURE_WRAP_T, GLES20.GL_CLAMP_TO_EDGE)

        val st = SurfaceTexture(oesTextureId)
        st.setDefaultBufferSize(widthPx, heightPx)
        st.setOnFrameAvailableListener({ _ ->
            // SurfaceTexture frame-available callbacks fire on the
            // thread that created the SurfaceTexture (our GL thread).
            handler.post { drawFrameIfRunning() }
        }, handler)
        cameraSurfaceTextureInternal = st
    }

    private fun drawFrameIfRunning() {
        if (!running.get()) return
        val st = cameraSurfaceTextureInternal ?: return
        val frameStartNs = System.nanoTime()
        try {
            st.updateTexImage()
            st.getTransformMatrix(stMatrix)
        } catch (e: Exception) {
            Timber.w(e, "updateTexImage failed")
            return
        }

        // 1. Draw to the encoder Surface (current EGL surface). PTS
        //    anchored to the SurfaceTexture frame timestamp (CLOCK_BOOTTIME
        //    ns — MediaCodec accepts this; the muxer normalizes via the
        //    bundle's anchor).
        var encoderSwapNs = 0L
        if (eglSurface != EGL14.EGL_NO_SURFACE) {
            drawFullscreenQuad(widthPx, heightPx)
            EGLExt.eglPresentationTimeANDROID(eglDisplay, eglSurface, st.timestamp)
            val swapStart = System.nanoTime()
            if (!EGL14.eglSwapBuffers(eglDisplay, eglSurface)) {
                Timber.w("eglSwapBuffers (encoder) failed: 0x%x", EGL14.eglGetError())
            }
            encoderSwapNs = System.nanoTime() - swapStart
        }

        // 2. Draw to the preview Surface if attached. No PTS — display
        //    only. The preview Surface dimensions are queried below and
        //    then used to centre an encoder-aspect rectangle inside them,
        //    rather than filling the whole SurfaceView (WYSIWYG, below).
        var previewSwapNs = 0L
        val previewSurface = eglPreviewSurface
        if (previewSurface != EGL14.EGL_NO_SURFACE) {
            if (!EGL14.eglMakeCurrent(eglDisplay, previewSurface, previewSurface, eglContext)) {
                Timber.w("eglMakeCurrent (preview) failed: 0x%x", EGL14.eglGetError())
                if (eglSurface != EGL14.EGL_NO_SURFACE) {
                    EGL14.eglMakeCurrent(eglDisplay, eglSurface, eglSurface, eglContext)
                }
                return
            }
            val pw = IntArray(1)
            val ph = IntArray(1)
            EGL14.eglQuerySurface(eglDisplay, previewSurface, EGL14.EGL_WIDTH, pw, 0)
            EGL14.eglQuerySurface(eglDisplay, previewSurface, EGL14.EGL_HEIGHT, ph, 0)
            if (previewDimsLogged.compareAndSet(false, true)) {
                // One-shot diagnostic at first preview draw. Includes the
                // full stMatrix (Mediatek can return crop + flip
                // combinations that are not pure rotation) and the GL
                // viewport state actually programmed.
                val rotDeg = ((sourceRotationDegrees % 360) + 360) % 360
                val rotSrcW = if (rotDeg == 90 || rotDeg == 270) sourceHeightPx else sourceWidthPx
                val rotSrcH = if (rotDeg == 90 || rotDeg == 270) sourceWidthPx else sourceHeightPx
                val contentRatio = rotSrcW.toFloat() / rotSrcH
                val viewportRatio = pw[0].toFloat() / ph[0]
                Timber.tag("StreamMetrics").i(
                    "previewCoverFitDims previewEglW=%d previewEglH=%d " +
                        "srcW=%d srcH=%d rotDeg=%d rotatedSrcW=%d rotatedSrcH=%d " +
                        "contentRatio=%.4f viewportRatio=%.4f",
                    pw[0], ph[0],
                    sourceWidthPx, sourceHeightPx, sourceRotationDegrees,
                    rotSrcW, rotSrcH,
                    contentRatio, viewportRatio
                )
                Timber.tag("StreamMetrics").i(
                    "previewStMatrix col0=[%.3f,%.3f,%.3f,%.3f] col1=[%.3f,%.3f,%.3f,%.3f] " +
                        "col2=[%.3f,%.3f,%.3f,%.3f] col3=[%.3f,%.3f,%.3f,%.3f]",
                    stMatrix[0], stMatrix[1], stMatrix[2], stMatrix[3],
                    stMatrix[4], stMatrix[5], stMatrix[6], stMatrix[7],
                    stMatrix[8], stMatrix[9], stMatrix[10], stMatrix[11],
                    stMatrix[12], stMatrix[13], stMatrix[14], stMatrix[15]
                )
                val vp = IntArray(4)
                GLES20.glGetIntegerv(GLES20.GL_VIEWPORT, vp, 0)
                Timber.tag("StreamMetrics").i(
                    "previewGlViewport x=%d y=%d w=%d h=%d (compare with previewEglW/H above)",
                    vp[0], vp[1], vp[2], vp[3]
                )
            }
            // WYSIWYG (2026-06-03) — render the preview into a rectangle of the
            // ENCODER aspect (widthPx:heightPx), centered in the preview surface
            // with black bars, and feed THOSE dims to the fit. The on-screen
            // framing then matches the recorded .mp4 EXACTLY (same fit, same
            // crop, same derived vscale). Using the full preview surface (a
            // different aspect) reframed the content and diverged from it.
            val encAspect = widthPx.toFloat() / heightPx
            val rectW: Int
            val rectH: Int
            if (pw[0].toFloat() / ph[0] >= encAspect) {
                rectH = ph[0]; rectW = (ph[0] * encAspect).toInt()
            } else {
                rectW = pw[0]; rectH = (pw[0] / encAspect).toInt()
            }
            drawFullscreenQuad(rectW, rectH, (pw[0] - rectW) / 2, (ph[0] - rectH) / 2)
            val previewSwapStart = System.nanoTime()
            if (!EGL14.eglSwapBuffers(eglDisplay, previewSurface)) {
                Timber.w("eglSwapBuffers (preview) failed: 0x%x", EGL14.eglGetError())
            }
            previewSwapNs = System.nanoTime() - previewSwapStart
            if (eglSurface != EGL14.EGL_NO_SURFACE) {
                EGL14.eglMakeCurrent(eglDisplay, eglSurface, eglSurface, eglContext)
            }
        }

        // Frame-rate metrics — accumulate this frame's timings and emit
        // a windowed summary every FRAME_METRICS_WINDOW_NS.
        val frameEndNs = System.nanoTime()
        val frameDurNs = frameEndNs - frameStartNs
        if (frMetricsWindowStartNs == 0L) {
            frMetricsWindowStartNs = frameEndNs
        } else {
            frMetricsFrameCount += 1
            frMetricsTotalDrawNs += frameDurNs
            frMetricsTotalEncoderSwapNs += encoderSwapNs
            frMetricsTotalPreviewSwapNs += previewSwapNs
            if (frameDurNs > frMetricsMaxFrameNs) frMetricsMaxFrameNs = frameDurNs
            if (encoderSwapNs > frMetricsMaxEncoderSwapNs) frMetricsMaxEncoderSwapNs = encoderSwapNs
            if (previewSwapNs > frMetricsMaxPreviewSwapNs) frMetricsMaxPreviewSwapNs = previewSwapNs

            val elapsedNs = frameEndNs - frMetricsWindowStartNs
            if (elapsedNs >= FRAME_METRICS_WINDOW_NS) {
                val fps = frMetricsFrameCount * 1_000_000_000.0 / elapsedNs
                val avgFrameMs = frMetricsTotalDrawNs.toDouble() / frMetricsFrameCount / 1e6
                val avgEncSwapMs =
                    frMetricsTotalEncoderSwapNs.toDouble() / frMetricsFrameCount / 1e6
                val avgPrevSwapMs =
                    frMetricsTotalPreviewSwapNs.toDouble() / frMetricsFrameCount / 1e6
                Timber.tag("StreamMetrics").i(
                    "glFrameRate fps=%.1f n=%d avgFrameMs=%.2f avgEncSwapMs=%.2f avgPrevSwapMs=%.2f maxFrameMs=%.2f maxEncSwapMs=%.2f maxPrevSwapMs=%.2f preview=%b",
                    fps, frMetricsFrameCount, avgFrameMs, avgEncSwapMs, avgPrevSwapMs,
                    frMetricsMaxFrameNs / 1e6, frMetricsMaxEncoderSwapNs / 1e6,
                    frMetricsMaxPreviewSwapNs / 1e6,
                    eglPreviewSurface != EGL14.EGL_NO_SURFACE
                )
                frMetricsWindowStartNs = frameEndNs
                frMetricsFrameCount = 0
                frMetricsTotalDrawNs = 0L
                frMetricsTotalEncoderSwapNs = 0L
                frMetricsTotalPreviewSwapNs = 0L
                frMetricsMaxFrameNs = 0L
                frMetricsMaxEncoderSwapNs = 0L
                frMetricsMaxPreviewSwapNs = 0L
            }
        }
    }

    private fun drawFullscreenQuad(viewportW: Int, viewportH: Int, vpX: Int = 0, vpY: Int = 0) {
        GLES20.glClearColor(0f, 0f, 0f, 1f)
        // Clear the WHOLE framebuffer first (glClear ignores the viewport), so
        // the letterbox bars around a smaller preview viewport stay black.
        GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT)
        // vpX/vpY let the preview pass render into a centered encoder-aspect
        // rectangle (WYSIWYG letterbox) ; the encoder pass uses 0,0 (default).
        GLES20.glViewport(vpX, vpY, viewportW, viewportH)
        // One-shot diagnostic per pass — confirm the driver honoured our
        // glViewport request. If GL_VIEWPORT != (viewportW, viewportH)
        // the framebuffer was smaller than the EGL surface promised.
        val isEncoderPass = viewportW == widthPx && viewportH == heightPx
        val shouldLog = if (isEncoderPass) {
            encoderDrawDimsLogged.compareAndSet(false, true)
        } else {
            previewDrawDimsLogged.compareAndSet(false, true)
        }
        if (shouldLog) {
            val vp = IntArray(4)
            GLES20.glGetIntegerv(GLES20.GL_VIEWPORT, vp, 0)
            Timber.tag("StreamMetrics").i(
                "drawFullscreenQuad pass=%s requestedW=%d requestedH=%d effectiveX=%d effectiveY=%d effectiveW=%d effectiveH=%d",
                if (isEncoderPass) "encoder" else "preview",
                viewportW, viewportH, vp[0], vp[1], vp[2], vp[3]
            )
        }
        GLES20.glUseProgram(program)

        GLES20.glActiveTexture(GLES20.GL_TEXTURE0)
        GLES20.glBindTexture(GLES11Ext.GL_TEXTURE_EXTERNAL_OES, oesTextureId)

        // Letterbox ("fit"), and never go back to a hand-tuned scale factor.
        // The old cover-fit used a geometric-mean NDC scale that was admittedly
        // never derived ("the exact mathematical cause has not been pinned
        // down") and was calibrated to the Seeker screen ratio, 0.4619 ; on the
        // OnePlus, 0.4813, it therefore distorted differently — that is the
        // device-dependent squash the operator reported. The letterbox is pure
        // geometry, NO fudge : scale the content uniformly by the smaller axis
        // magnification so it fits fully inside the viewport, and let the
        // glClear black show through as bars. Distortion-free on every
        // screen/sensor aspect, and the preview shows exactly the recorded frame
        // (WYSIWYG framing). (H2-B.20, 2026-05-24.)
        // Rotating by 90° or 270° maps the source's long axis to the display's
        // short axis, so swap width and height for the ratio.
        val rotDeg = ((sourceRotationDegrees % 360) + 360) % 360
        val rotatedSrcW: Float
        val rotatedSrcH: Float
        if (rotDeg == 90 || rotDeg == 270) {
            rotatedSrcW = sourceHeightPx.toFloat()
            rotatedSrcH = sourceWidthPx.toFloat()
        } else {
            rotatedSrcW = sourceWidthPx.toFloat()
            rotatedSrcH = sourceHeightPx.toFloat()
        }
        // magX / magY = absolute pixel magnification needed to fill the
        // viewport along each axis. fitMag = min(magX, magY) scales the source
        // UNIFORMLY so it fits inside the viewport : the larger axis fills
        // edge-to-edge, the other leaves black bars.
        //
        // Both passes are handed a viewport of the ENCODER aspect — the preview
        // gets a centred rectangle of that aspect — so whenever the rotated
        // source carries that same aspect, which is the shipped case, magX and
        // magY coincide up to rounding and the fit is the identity on both axes.
        // The black seen around the preview therefore comes from elsewhere, and
        // from two places rather than one. Centring the encoder-aspect rectangle
        // in a taller surface accounts for ~9% at the top and ~9% at the bottom
        // on the Seeker, whose preview EGL surface measures 1200×2598 (read off
        // the previewCoverFitDims one-shot above) : a 1200×2133 rectangle leaves
        // ~232 px at each end, painted black by the full-frame glClear. The
        // larger share comes from the derived vertical correction below, which
        // multiplies scaleY on top of the fit — 0.5625 in the shipped 16:9 mode,
        // so the quad covers about 56% of the rectangle's height. The final
        // geometry is deliberately not the identity. The resulting framing was
        // cross-checked against the Blackmagic app and the stock camera.
        //
        // When the source aspect differs — the A and D modes of the debug aspect
        // harness, or a 4:3-only sensor — the fit letterboxes it into the frame
        // instead of stretching it. The recording is evidence : it is not
        // distorted to fill the frame.
        val magX = viewportW.toFloat() / rotatedSrcW
        val magY = viewportH.toFloat() / rotatedSrcH
        val fitMag = kotlin.math.min(magX, magY)
        // Operator-requested 20% zoom-in to match the Blackmagic camera app
        // framing (H2-B.23). Uniform magnification (both axes × ZOOM_IN)
        // preserves the corrected aspect ; the overflow past the viewport is
        // clipped, cropping the sides and gaining center readability. Applied
        // to both passes, recording and preview — but inert in the shipped
        // mode F, where ZOOM_IN is 1.0. Only the two "fudge" diagnostic modes,
        // A and E, set 1.2 ; the mode table is in
        // StreamPreferences.KEY_DEBUG_ASPECT_MODE and StreamRecordingService
        // derives the three GL fields from it at each camera bind.
        val scaleX = (fitMag / magX) * ZOOM_IN
        // Anamorphic vertical correction. The recorded and previewed image comes
        // out stretched vertically by exactly the source's landscape aspect
        // ratio : the 4-corner squish matrix (cv2 fitEllipse,
        // {4:3,16:9}x{fudge,identity}) fits H/W = (rotatedSrcH / rotatedSrcW) *
        // vscale on all four points. So a circle reads round IFF
        //     vscale = rotatedSrcW / rotatedSrcH   (= 1 / sourceLandscapeAspect).
        // For 4:3 that is 960/1280 = 0.75 — exactly the old hand-tuned
        // ANAMORPHIC_VSCALE, now explained ; for 16:9 it is 720/1280 = 0.5625.
        // DERIVE_VSCALE computes it from the negotiated dims, which makes the
        // correction device- and aspect-independent : don't go back to tuning a
        // constant by hand on one phone. (H2-B.22, root-caused 2026-06-02.)
        val effectiveVScale =
            if (DERIVE_VSCALE) (rotatedSrcW / rotatedSrcH) else ANAMORPHIC_VSCALE
        val scaleY = (fitMag / magY) * effectiveVScale * ZOOM_IN
        // MVP = Scale(fit) only — NO rotation in MVP. In-vivo on Seeker
        // 2026-05-17 we observed that applying ±rotDeg here produced a
        // 90°-rotated / X-Y-transposed image : Mediatek's
        // SurfaceTexture.getTransformMatrix already includes the
        // camera-mount-to-display rotation, so re-applying it
        // double-rotates. We keep [rotDeg] only to pick the rotated
        // source dims for the fit math above, never in the quad geometry.
        val mvp = FloatArray(16).also {
            Matrix.setIdentityM(it, 0)
            Matrix.scaleM(it, 0, scaleX, scaleY, 1f)
        }
        GLES20.glUniformMatrix4fv(uMvpMatrixLoc, 1, false, mvp, 0)
        // stMatrix is left untouched : we only need the OEM's Y-flip /
        // rotation. All aspect work is in the MVP scale above.
        GLES20.glUniformMatrix4fv(uStMatrixLoc, 1, false, stMatrix, 0)

        GLES20.glEnableVertexAttribArray(aPositionLoc)
        GLES20.glVertexAttribPointer(
            aPositionLoc, 2, GLES20.GL_FLOAT, false, 0, fullscreenQuadPositions
        )
        GLES20.glEnableVertexAttribArray(aTexCoordLoc)
        GLES20.glVertexAttribPointer(
            aTexCoordLoc, 2, GLES20.GL_FLOAT, false, 0, fullscreenQuadTexCoords
        )

        GLES20.glDrawArrays(GLES20.GL_TRIANGLE_STRIP, 0, 4)

        GLES20.glDisableVertexAttribArray(aPositionLoc)
        GLES20.glDisableVertexAttribArray(aTexCoordLoc)
    }

    private fun createProgram(vertexSrc: String, fragmentSrc: String): Int {
        val vs = compileShader(GLES20.GL_VERTEX_SHADER, vertexSrc)
        val fs = compileShader(GLES20.GL_FRAGMENT_SHADER, fragmentSrc)
        val p = GLES20.glCreateProgram()
        GLES20.glAttachShader(p, vs)
        GLES20.glAttachShader(p, fs)
        GLES20.glLinkProgram(p)
        val linked = IntArray(1)
        GLES20.glGetProgramiv(p, GLES20.GL_LINK_STATUS, linked, 0)
        check(linked[0] == GLES20.GL_TRUE) {
            "Program link failed: ${GLES20.glGetProgramInfoLog(p)}"
        }
        GLES20.glDeleteShader(vs)
        GLES20.glDeleteShader(fs)
        return p
    }

    private fun compileShader(type: Int, source: String): Int {
        val s = GLES20.glCreateShader(type)
        GLES20.glShaderSource(s, source)
        GLES20.glCompileShader(s)
        val compiled = IntArray(1)
        GLES20.glGetShaderiv(s, GLES20.GL_COMPILE_STATUS, compiled, 0)
        check(compiled[0] == GLES20.GL_TRUE) {
            "Shader compile failed: ${GLES20.glGetShaderInfoLog(s)}"
        }
        return s
    }

    companion object {
        // Empirical vertical anamorphic correction factor, read on the GL thread
        // in drawFullscreenQuad (1.0 = no correction). The observed distortion
        // is a ~1.33x vertical stretch, so 1/1.33 ≈ 0.75 undoes it. Tune against
        // a round reference ; >0.75 if still too tall, <0.75 if over-corrected
        // (now too wide/flat).
        //
        // This field and the two below are deliberately not `const` : since
        // 2026-06-02 StreamRecordingService overwrites all three at every camera
        // bind from the debug aspect mode, hence @Volatile. The initialisers
        // here are the values of diagnostic mode A and do not survive that first
        // bind — the shipped mode is F, which derives the vscale and never reads
        // this constant. Turning any of them back into a `const val` does not
        // compile : the assignments in StreamRecordingService.startCamera are
        // what would break, and the A/B harness that measures the squash on a
        // new device needs them settable at bind time.
        @Volatile
        var ANAMORPHIC_VSCALE = 0.75f

        // Operator-requested zoom-in (1.2 = +20%) to crop the sides, match the
        // Blackmagic camera app framing and improve center readability ; 1.0 =
        // no zoom. Runtime-mutable like ANAMORPHIC_VSCALE above : 1.2 is the
        // diagnostic mode A value, the shipped mode F sets 1.0.
        @Volatile
        var ZOOM_IN = 1.2f

        // 2026-06-02 — mode F. When true, drawFullscreenQuad DERIVES the
        // vertical anamorphic correction from the negotiated source dims
        // (vscale = rotatedSrcW / rotatedSrcH = 1 / sourceLandscapeAspect)
        // instead of the hard-coded ANAMORPHIC_VSCALE. Device- and
        // aspect-independent ; validated by the 4-corner squish matrix.
        // Set by StreamRecordingService from the debug aspect mode.
        @Volatile
        var DERIVE_VSCALE = false

        // EGL_RECORDABLE_ANDROID = 0x3142, Khronos extension defined in
        // <EGL/eglext.h>. Not in EGL14 constants — declare ourselves.
        private const val EGL_RECORDABLE_ANDROID = 0x3142

        // Frame-rate metrics window — emit one summary every 5 seconds
        // (matches the rolling chunk interval, so each chunk gets one
        // window of measurements).
        private const val FRAME_METRICS_WINDOW_NS = 5_000_000_000L

        // Fullscreen triangle-strip quad : 4 vertices covering NDC
        // [-1..1] in clockwise winding. Texture coords match the
        // SurfaceTexture's natural orientation; the transform matrix
        // applied via uSTMatrix handles any camera-side rotation.
        private val fullscreenQuadPositions: FloatBuffer =
            ByteBuffer.allocateDirect(8 * 4)
                .order(ByteOrder.nativeOrder())
                .asFloatBuffer()
                .apply {
                    put(floatArrayOf(
                        -1f, -1f,
                         1f, -1f,
                        -1f,  1f,
                         1f,  1f,
                    ))
                    position(0)
                }

        private val fullscreenQuadTexCoords: FloatBuffer =
            ByteBuffer.allocateDirect(8 * 4)
                .order(ByteOrder.nativeOrder())
                .asFloatBuffer()
                .apply {
                    put(floatArrayOf(
                        0f, 0f,
                        1f, 0f,
                        0f, 1f,
                        1f, 1f,
                    ))
                    position(0)
                }
    }
}

// #8: GL-thread op timeout — generous vs the 1-5 ms nominal so healthy
// contention is not a false positive, but a wedged driver cannot freeze the
// rotation cadence forever.
private const val GL_OP_TIMEOUT_MS = 2000L

/** Thrown when a [GlVideoPipeline] GL-thread op doesn't complete within the timeout. */
class GlPipelineStalledException(message: String) : RuntimeException(message)
