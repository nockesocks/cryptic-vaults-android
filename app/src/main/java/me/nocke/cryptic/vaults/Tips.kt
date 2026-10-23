package me.nocke.cryptic.vaults

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast

/** Where tips go. Cryptic Vaults has no network access: the tip page opens in the browser, which fetches the live invoice or price. */
object Tips {
    /** The tip web page (Lightning via Strike, Monero at the live price); `?amount=N` preselects $N, `app` tells the page which app the tip is for. */
    const val PAGE = "https://nockesocks.github.io/tip/"

    fun open(context: Context, usd: Int) {
        runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("$PAGE?amount=$usd&app=cryptic-vaults-android"))) }
            .onFailure { Toast.makeText(context, "No browser on this phone can open the tip page.", Toast.LENGTH_LONG).show() }
    }
}
