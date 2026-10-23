package me.nocke.cryptic.vaults

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView

/** The app's view kit in the app's palette (res/values/colors.xml): cards, buttons, labels. */
class Ui(private val c: Context) {
    fun dp(v: Int) = (v * c.resources.displayMetrics.density).toInt()
    private fun color(id: Int) = c.getColor(id)

    private fun shape(fill: Int, radius: Int, stroke: Int? = null) = GradientDrawable().apply {
        setColor(fill); cornerRadius = dp(radius).toFloat(); stroke?.let { setStroke(dp(1), it) }
    }

    private fun lp(w: Int = LinearLayout.LayoutParams.MATCH_PARENT, h: Int = LinearLayout.LayoutParams.WRAP_CONTENT, top: Int = 0, weight: Float = 0f) =
        LinearLayout.LayoutParams(w, h, weight).apply { topMargin = dp(top) }

    fun column(padding: Int = 0) = LinearLayout(c).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(padding), dp(padding), dp(padding), dp(padding)) }

    fun header(title: String, subtitle: String) = column().apply {
        setPadding(dp(4), dp(8), dp(4), dp(8))
        addView(TextView(c).apply { text = title; textSize = 28f; setTextColor(color(R.color.text)); typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL) })
        addView(TextView(c).apply { text = subtitle; textSize = 14f; setTextColor(color(R.color.text_muted)) }, lp(top = 2))
    }

    fun section(label: String) = TextView(c).apply {
        text = label.uppercase(); textSize = 12f; letterSpacing = 0.12f
        setTextColor(color(R.color.accent_light)); typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
        layoutParams = lp(top = 24).apply { leftMargin = dp(4); bottomMargin = dp(4) }
    }

    fun card() = column(16).apply { background = shape(color(R.color.surface), 14); layoutParams = lp(top = 8) }

    /** A hint, not an input: a soft filled panel with an icon, no outline. */
    fun empty(text: String, icon: Int = R.drawable.ic_usb) = LinearLayout(c).apply {
        gravity = Gravity.CENTER_VERTICAL
        background = shape(color(R.color.accent_soft), 14); setPadding(dp(16), dp(14), dp(16), dp(14))
        layoutParams = lp(top = 8)
        addView(ImageView(c).apply { setImageResource(icon); imageTintList = ColorStateList.valueOf(color(R.color.accent_light)); alpha = 0.8f },
            LinearLayout.LayoutParams(dp(20), dp(20)))
        addView(TextView(c).apply { this.text = text; textSize = 14f; setTextColor(color(R.color.text_muted)) },
            lp(w = 0, weight = 1f).apply { leftMargin = dp(12) })
    }

    /** Icon tile + title + subtitle. */
    fun item(icon: Int, title: String, subtitle: String?, tint: Boolean = true) = LinearLayout(c).apply {
        gravity = Gravity.CENTER_VERTICAL
        addView(FrameLayout(c).apply {
            background = shape(color(R.color.accent_soft), 10)
            if (tint) addView(ImageView(c).apply { setImageResource(icon); imageTintList = ColorStateList.valueOf(color(R.color.accent_light)) },
                FrameLayout.LayoutParams(dp(22), dp(22), Gravity.CENTER))
            else addView(ImageView(c).apply { setImageResource(icon) }, FrameLayout.LayoutParams(dp(40), dp(40), Gravity.CENTER))
        }, LinearLayout.LayoutParams(dp(40), dp(40)))
        addView(column().apply {
            addView(TextView(c).apply { text = title; textSize = 16f; setTextColor(color(R.color.text)); typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL) })
            if (subtitle != null) addView(TextView(c).apply { text = subtitle; textSize = 13f; setTextColor(color(R.color.text_muted)) })
        }, lp(w = 0, weight = 1f).apply { leftMargin = dp(12) })
    }

    enum class Kind { PRIMARY, SECONDARY, DANGER }

    fun button(label: String, kind: Kind = Kind.SECONDARY, onClick: () -> Unit) = TextView(c).apply {
        text = label; textSize = 14f; gravity = Gravity.CENTER; isClickable = true; isFocusable = true
        typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
        setPadding(dp(14), dp(10), dp(14), dp(10)); minHeight = dp(44)
        val (fill, stroke, fg) = when (kind) {
            Kind.PRIMARY -> Triple(color(R.color.accent), null, color(R.color.on_accent))
            Kind.SECONDARY -> Triple(color(R.color.surface_high), color(R.color.divider), color(R.color.text))
            Kind.DANGER -> Triple(color(R.color.surface_high), color(R.color.danger), color(R.color.danger))
        }
        setTextColor(fg)
        background = RippleDrawable(ColorStateList.valueOf(0x33FFFFFF), shape(fill, 10, stroke), shape(0xFFFFFFFF.toInt(), 10))
        setOnClickListener { onClick() }
    }

    /** A thin accent-coloured divider between groups of settings; [short] = a centred one a third as wide. */
    fun rule(short: Boolean = false) = View(c).apply {
        setBackgroundColor(color(R.color.accent_light)); alpha = 0.85f
        layoutParams = LinearLayout.LayoutParams(if (short) dp(110) else LinearLayout.LayoutParams.MATCH_PARENT, dp(1)).apply {
            topMargin = dp(24); bottomMargin = dp(8); leftMargin = dp(4); rightMargin = dp(4); if (short) gravity = Gravity.CENTER_HORIZONTAL
        }
    }

    /** A big square-ish button: icon over a label (the tip sizes). */
    fun tile(icon: Int, label: String, onClick: () -> Unit) = LinearLayout(c).apply {
        orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER; isClickable = true; isFocusable = true
        setPadding(dp(6), dp(8), dp(6), dp(7))
        background = RippleDrawable(ColorStateList.valueOf(0x33FFFFFF), shape(color(R.color.surface_high), 12, color(R.color.divider)), shape(0xFFFFFFFF.toInt(), 12))
        addView(ImageView(c).apply { setImageResource(icon); imageTintList = ColorStateList.valueOf(color(R.color.accent_light)) }, LinearLayout.LayoutParams(dp(26), dp(26)))
        addView(TextView(c).apply { text = label; textSize = 13f; setTextColor(color(R.color.text_muted)); typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL); gravity = Gravity.CENTER },
            lp(top = 3))
        setOnClickListener { onClick() }
    }

    /** A raised panel inside a card, like the tip cups: a title, a muted line, tappable when [onClick] is given. */
    fun subcard(title: String, subtitle: String, onClick: (() -> Unit)? = null) = column().apply {
        setPadding(dp(14), dp(12), dp(14), dp(12)); layoutParams = lp(top = 10)
        val panel = shape(color(R.color.surface_high), 12, color(R.color.divider))
        background = if (onClick == null) panel else RippleDrawable(ColorStateList.valueOf(0x33FFFFFF), panel, shape(0xFFFFFFFF.toInt(), 12))
        addView(TextView(c).apply { text = title; textSize = 16f; setTextColor(color(R.color.text)); typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL) })
        addView(TextView(c).apply { text = subtitle; textSize = 13f; setTextColor(color(R.color.text_muted)); setLineSpacing(0f, 1.1f) }, lp(top = 2))
        if (onClick != null) { isClickable = true; isFocusable = true; setOnClickListener { onClick() } }
    }

    /** Buttons side by side, sharing the width. */
    fun row(vararg views: View, top: Int = 14) = LinearLayout(c).apply {
        layoutParams = lp(top = top)
        views.forEachIndexed { i, v -> addView(v, lp(w = 0, weight = 1f).apply { if (i > 0) leftMargin = dp(8) }) }
    }

    fun full(v: View, top: Int = 8) = v.apply { layoutParams = lp(top = top) }

    fun usage(used: Long, total: Long) = ProgressBar(c, null, android.R.attr.progressBarStyleHorizontal).apply {
        max = 1000; progress = if (total > 0) (used * 1000 / total).toInt() else 0
        progressTintList = ColorStateList.valueOf(color(R.color.accent))
        progressBackgroundTintList = ColorStateList.valueOf(color(R.color.divider))
        layoutParams = lp(h = dp(6), top = 12)
    }

    /** One of several options as rounded chips, [perRow] to a line; [onChange] gets the chosen value. */
    fun chips(options: List<Pair<String, String>>, selected: String, perRow: Int = options.size, onChange: (String) -> Unit) = column().apply {
        setPadding(0, dp(6), 0, dp(2))
        var current = selected
        val buttons = ArrayList<TextView>()
        fun paint() = buttons.forEachIndexed { i, b ->
            val on = options[i].first == current
            b.background = shape(color(if (on) R.color.accent else R.color.surface_high), 10, if (on) null else color(R.color.divider))   // same corners as the buttons
            b.setTextColor(color(if (on) R.color.on_accent else R.color.text))
        }
        options.chunked(perRow).forEachIndexed { r, line ->
            addView(LinearLayout(c).apply {
                line.forEach { (value, text) ->
                    val b = TextView(c).apply {
                        this.text = text; gravity = Gravity.CENTER; textSize = 14f; setPadding(dp(18), dp(8), dp(18), dp(8))
                        setOnClickListener { current = value; paint(); onChange(value) }
                    }
                    buttons.add(b); addView(b, LinearLayout.LayoutParams(-2, -2).apply { rightMargin = dp(8) })
                }
            }, lp(top = if (r == 0) 0 else 8))
        }
        paint()
    }

    /** A sub-screen's top bar: back arrow + title. */
    fun back(title: String, onBack: () -> Unit) = LinearLayout(c).apply {
        gravity = Gravity.CENTER_VERTICAL; setPadding(0, dp(4), 0, dp(8))
        addView(TextView(c).apply {
            text = "←"; textSize = 24f; setTextColor(color(R.color.accent_light)); setPadding(dp(4), dp(4), dp(16), dp(4))
            isClickable = true; contentDescription = "Back"; setOnClickListener { onBack() }
        })
        addView(TextView(c).apply { text = title; textSize = 22f; setTextColor(color(R.color.text)); typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL) })
    }

    /** A statement line, H1-sized. */
    fun heading(text: CharSequence) = TextView(c).apply {
        this.text = text; textSize = 22f; setTextColor(color(R.color.text)); typeface = Typeface.create("sans-serif", Typeface.BOLD)
        setLineSpacing(0f, 1.1f); layoutParams = lp(top = 16)
    }

    fun paragraph(text: String, bold: Boolean = false) = TextView(c).apply {
        this.text = text; textSize = if (bold) 15f else 14f; setLineSpacing(0f, 1.15f)
        setTextColor(color(if (bold) R.color.text else R.color.text_muted))
        if (bold) typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
        layoutParams = lp(top = if (bold) 16 else 10)
    }

    fun bullets(items: List<String>) = column().apply {
        layoutParams = lp(top = 6)
        items.forEach { t ->
            addView(LinearLayout(c).apply {
                addView(TextView(c).apply { text = "•"; textSize = 14f; setTextColor(color(R.color.accent_light)) }, LinearLayout.LayoutParams(dp(16), -2))
                addView(TextView(c).apply { text = t; textSize = 14f; setTextColor(color(R.color.text_muted)); setLineSpacing(0f, 1.15f) }, lp(w = 0, weight = 1f))
            }, lp(top = 4))
        }
    }

    fun mono(text: String) = TextView(c).apply {
        this.text = text; typeface = Typeface.MONOSPACE; textSize = 12f; setTextIsSelectable(true); setTextColor(color(R.color.text))
        background = shape(color(R.color.surface_high), 8); setPadding(dp(10), dp(8), dp(10), dp(8)); layoutParams = lp(top = 10)
    }

    fun note(text: String, top: Int = 10) = TextView(c).apply {
        this.text = text; textSize = 13f; setTextColor(color(R.color.text_muted)); layoutParams = lp(top = top)
    }

    fun link(text: String, size: Float = 14f, onClick: () -> Unit) = TextView(c).apply {
        this.text = text; textSize = size; setTextColor(color(R.color.accent_light)); gravity = Gravity.CENTER
        setPadding(dp(12), dp(14), dp(12), dp(14)); isClickable = true; setOnClickListener { onClick() }
        layoutParams = lp(top = 20)
    }
}
