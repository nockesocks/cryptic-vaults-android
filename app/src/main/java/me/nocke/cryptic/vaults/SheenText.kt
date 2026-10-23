package me.nocke.cryptic.vaults

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.LinearGradient
import android.graphics.Matrix
import android.graphics.Shader
import android.graphics.Typeface
import android.view.animation.LinearInterpolator
import android.widget.TextView

/**
 * A title in the accent colours. [reveal] decodes it from cycling letters and symbols (like a hash turning into the
 * word), settling left to right, then sweeps one sheen across it. Still (just the word)
 * when animations are off.
 */
class SheenText(c: Context) : TextView(c) {
    private val shaderMatrix = Matrix()
    private var shader: LinearGradient? = null
    private var animator: ValueAnimator? = null

    init { typeface = Typeface.create("sans-serif-medium", Typeface.BOLD); letterSpacing = 0.02f }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        val base = context.getColor(R.color.accent); val hi = context.getColor(R.color.accent_light); val sheen = context.getColor(R.color.sheen)
        // a base gradient across the word, with the sheen band in the middle of a 3x-wide shader that slides across
        shader = LinearGradient(0f, 0f, w * 3f, 0f, intArrayOf(base, hi, base, sheen, base, hi, base),
            floatArrayOf(0f, 0.2f, 0.44f, 0.5f, 0.56f, 0.8f, 1f), Shader.TileMode.CLAMP)
        paint.shader = shader
        place(-2f * w)
        if (playing) start(w)
    }

    private var playing = false

    /** Sweeps the band across once. */
    fun play() { playing = true; if (width > 0) start(width) }

    /**
     * Decode into [word], then one sheen: it starts as [word].length + 4 random glyphs and shrinks to the word as letters
     * settle left to right. The view wraps the current text every frame, so no glyph is ever cut off.
     */
    fun reveal(word: String, settled: () -> Unit = {}) {
        text = word
        if (!ValueAnimator.areAnimatorsEnabled()) { settled(); return }
        val extra = 4
        val glyphs = "0123456789abcdef#\$%&@*+=/<>{}[]?!~^"
        val rnd = java.util.Random()
        var last = -1L
        ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 1200; interpolator = LinearInterpolator()
            addUpdateListener { va ->
                val now = va.currentPlayTime / 55                  // new random glyphs every ~55 ms
                if (now == last && va.animatedFraction < 1f) return@addUpdateListener
                last = now
                val f = va.animatedFraction
                val settled = ((f * 1.25f - 0.25f) * word.length).toInt().coerceIn(0, word.length)
                val length = word.length + Math.round(extra * (1f - (f / 0.8f).coerceAtMost(1f)))   // 11 → 7 by 80 %
                text = word.substring(0, settled) + String(CharArray(maxOf(0, length - settled)) { glyphs[rnd.nextInt(glyphs.length)] })
            }
            addListener(object : android.animation.AnimatorListenerAdapter() {
                override fun onAnimationEnd(a: android.animation.Animator) { text = word; settled(); play() }
            })
            start()
        }
    }

    private fun place(x: Float) { shaderMatrix.setTranslate(x, 0f); shader?.setLocalMatrix(shaderMatrix); invalidate() }

    private fun start(w: Int) {
        animator?.cancel()
        if (!ValueAnimator.areAnimatorsEnabled() || w == 0) { place(-w.toFloat()); return }
        animator = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 1300; interpolator = android.view.animation.DecelerateInterpolator(1.4f)
            addUpdateListener { va -> place(-2f * w + (va.animatedValue as Float) * 2f * w) }
            start()
        }
    }

    override fun onDetachedFromWindow() { animator?.cancel(); super.onDetachedFromWindow() }
}
