package me.nocke.cryptic.vaults

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.graphics.Shader
import android.view.View
import android.view.animation.LinearInterpolator

/**
 * The launcher padlock, drawn live: it starts open in the splash's end pose (shackle raised and turned out to the right
 * about its right leg, see drawable/splash_icon.xml); on [play] it swings back left, drops and locks with
 * a small bounce; a burst of light then flares from the lock (spilling past the icon, so the parent must not clip) and
 * [onSnap] starts the title's sheen. Drawn in the launcher icon's 108-unit space, showing the same 72-unit circle the
 * splash shows (Android crops splash icons to it), with the padlock at 0.66 so the turned-out shackle fits while the
 * body stays centred — so the splash circle lands exactly on this one.
 */
class LockIcon(c: Context, shut: Boolean = false, private val onSnap: () -> Unit = {}) : View(c) {
    private val bg = Paint(Paint.ANTI_ALIAS_FLAG)
    private val body = Paint(Paint.ANTI_ALIAS_FLAG)
    private val shackle = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE; strokeWidth = 6f; strokeCap = Paint.Cap.ROUND; color = 0xFFB5ABFC.toInt()
    }
    private val hole = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0xFF161826.toInt() }
    private val light = Paint(Paint.ANTI_ALIAS_FLAG)
    private var t = if (shut) 1f else 0f          // 0 open … 1 shut (shut = a still icon, e.g. in About)
    private var snapped = shut
    private var burst = -1f    // -1 none, 0…1 flaring
    private val glow = Paint(Paint.ANTI_ALIAS_FLAG)

    init {
        bg.shader = LinearGradient(0f, 0f, 108f, 108f, 0xFF262A60.toInt(), 0xFF161826.toInt(), Shader.TileMode.CLAMP)
        body.shader = LinearGradient(30f, 49f, 78f, 83f, 0xFFB5ABFC.toInt(), 0xFF796CBF.toInt(), Shader.TileMode.CLAMP)
    }

    private var played = false

    /** Close it (once): swing, drop, lock, flare; with animations off, just shut. */
    fun play() {
        if (played) return
        played = true
        if (ValueAnimator.areAnimatorsEnabled()) animateShut() else { t = 1f; snapped = true; invalidate(); onSnap() }
    }

    private fun animateShut() {
        ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 1000; startDelay = 80; interpolator = LinearInterpolator()
            addUpdateListener { t = it.animatedValue as Float; invalidate() }
            addListener(object : android.animation.AnimatorListenerAdapter() {
                override fun onAnimationEnd(a: android.animation.Animator) { snapped = true; flare() }
            })
            start()
        }
    }

    /** The burst: a soft white flare growing from the lock and fading; the sheen sets off just after it starts. */
    private fun flare() {
        ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 800; interpolator = android.view.animation.DecelerateInterpolator()
            addUpdateListener { burst = it.animatedValue as Float; invalidate() }
            addListener(object : android.animation.AnimatorListenerAdapter() {
                override fun onAnimationEnd(a: android.animation.Animator) { burst = -1f; invalidate() }
            })
            start()
        }
        postDelayed({ onSnap() }, 120)
    }

    override fun onDraw(canvas: Canvas) {
        val s = minOf(width, height) / 72f
        canvas.save(); canvas.scale(s, s); canvas.translate(-18f, -18f)
        canvas.drawCircle(54f, 54f, 36f, bg)
        // phases: 0–0.45 swing the raised shackle over; 0.45–0.75 drop it; 0.75–1 snap (body bounce)
        val swing = ease((t / 0.45f).coerceIn(0f, 1f))
        val drop = ease(((t - 0.45f) / 0.3f).coerceIn(0f, 1f))
        val snap = ((t - 0.75f) / 0.25f).coerceIn(0f, 1f)
        val bounce = if (snap > 0f) 1f + 0.08f * kotlin.math.sin(snap * Math.PI).toFloat() else 1f

        canvas.save()
        canvas.scale(0.66f, 0.66f, 54f, 54f)
        canvas.translate(0f, -1.5f)                              // centre the shut padlock (shackle top 28 … body bottom 83)
        canvas.save()
        canvas.translate(0f, -7f * (1f - drop))                 // raised until it drops
        canvas.scale(-1f + 2f * swing, 1f, 66f, 51f)           // turned out to the right about the right leg; swings back left
        // the right leg is long: it stays in the body when the shackle is lifted
        canvas.drawPath(Path().apply { moveTo(42f, 51f); lineTo(42f, 43f); arcTo(RectF(42f, 31f, 66f, 55f), 180f, 180f); lineTo(66f, 63f) }, shackle)
        canvas.restore()

        canvas.save()
        canvas.scale(bounce, bounce, 54f, 66f)
        canvas.drawRoundRect(RectF(30f, 49f, 78f, 83f), 7f, 7f, body)
        canvas.drawCircle(54f, 62.5f, 4.5f, hole)
        canvas.drawPath(Path().apply { moveTo(51.6f, 66f); lineTo(50.5f, 73.5f); lineTo(57.5f, 73.5f); lineTo(56.4f, 66f); close() }, hole)
        light.color = if (snapped || snap > 0.5f) 0xFF7BC8A4.toInt() else 0xFF59506E.toInt()   // the drive light comes on when it locks
        canvas.drawCircle(70f, 77f, 2f, light)
        canvas.restore()
        canvas.restore()
        if (burst >= 0f) {
            val r = 10f + 36f * burst                              // stays around the icon
            val a = (Math.pow((1.0 - burst), 0.6) * 235).toInt()
            glow.shader = android.graphics.RadialGradient(54f, 64f, r, intArrayOf((a shl 24) or 0xF5F4FF, (a / 3 shl 24) or 0xB5ABFC, 0x00B5ABFC),
                floatArrayOf(0f, 0.45f, 1f), Shader.TileMode.CLAMP)
            canvas.drawCircle(54f, 64f, r, glow)
        }
        canvas.restore()
    }

    private fun ease(x: Float) = 1f - (1f - x) * (1f - x) * (1f - x)
}
