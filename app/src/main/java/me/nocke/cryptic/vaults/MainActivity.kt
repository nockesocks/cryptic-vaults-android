package me.nocke.cryptic.vaults

import android.Manifest
import android.app.AlertDialog
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.text.format.Formatter
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import me.nocke.cryptic.vaults.block.BlockDevice
import me.nocke.cryptic.vaults.block.Partitions
import me.nocke.cryptic.vaults.block.PfdBlockDevice
import me.nocke.cryptic.vaults.block.SliceBlockDevice
import me.nocke.cryptic.vaults.block.UsbBlockDevice
import me.nocke.cryptic.vaults.luks.Luks2
import me.nocke.cryptic.vaults.luks.WrongPassphraseException
import kotlin.concurrent.thread

class MainActivity : LockedActivity() {
    private lateinit var content: LinearLayout
    private val prefs by lazy { Prefs(this) }
    private val usb by lazy { getSystemService(UsbManager::class.java) }
    private val maintenance by lazy { Maintenance(this) }
    private val details by lazy { Details(this) }
    private enum class DriveAction { UNLOCK, FORMAT, WIPE, EDIT, DETAILS }
    private var pendingAction = DriveAction.UNLOCK
    private val refresh = { render() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs.applyTheme()
        if (savedInstanceState == null) splashScreen.setOnExitAnimationListener { flyIn(it) }
        val col = ui.column(16)
        col.addView(header())
        content = ui.column(); col.addView(content)
        setContentView(ScrollView(this).apply { addView(col); fitsSystemWindows = true; setBackgroundColor(getColor(R.color.bg)) })
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        val f = IntentFilter(ACTION_USB_PERMISSION).apply { addAction(UsbManager.ACTION_USB_DEVICE_DETACHED); addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED) }
        registerReceiver(usbEvents, f, RECEIVER_NOT_EXPORTED)
        whenUnlocked { handle(intent) }
        // no splash this time (warm start, recreate): close the header padlock on its own
        lockIcon.postDelayed({ whenUnlocked { if (!splashHandled) { lockIcon.play(); revealTitle() } } }, if (savedInstanceState == null) 1500 else 100)
    }

    private var splashHandled = false

    /**
     * The splash padlock (open, see drawable/splash_icon.xml) shrinks and flies into the header padlock's place; the
     * header padlock, hidden until then in the same open pose, takes over and closes. With app lock on, the splash
     * stays until the unlock: nothing of the home page shows before it.
     */
    private fun flyIn(v: android.window.SplashScreenView) {
        splashHandled = true
        if (locked && usesPhoneLock) { whenUnlocked { flyIn(v) }; return }
        // the app's own PIN or passphrase is typed on the cover, which the splash would hide: hand over to it at once
        if (locked) { v.remove(); whenUnlocked { lockIcon.play(); revealTitle() }; return }
        val icon = v.iconView
        if (icon == null || !android.animation.ValueAnimator.areAnimatorsEnabled()) { v.remove(); lockIcon.play(); revealTitle(); return }
        lockIcon.alpha = 0f
        val end = v.iconAnimationStart?.toEpochMilli()?.plus(v.iconAnimationDuration?.toMillis() ?: 0) ?: 0
        val wait = (end - System.currentTimeMillis()).coerceIn(0, 1000)
        icon.postDelayed({
            revealTitle()                              // decodes on its own clock as the home page shows through
            val from = IntArray(2).also { icon.getLocationOnScreen(it) }
            val to = IntArray(2).also { lockIcon.getLocationOnScreen(it) }
            // the splash shows a circle 2/3 of its icon view; the header padlock is that same circle at full size
            val scale = lockIcon.width.toFloat() / (icon.width * 2f / 3f)
            val dx = (to[0] + lockIcon.width / 2f) - (from[0] + icon.width / 2f)
            val dy = (to[1] + lockIcon.height / 2f) - (from[1] + icon.height / 2f)
            val bg = v.background?.mutate()
            android.animation.ValueAnimator.ofInt(255, 0).apply {
                duration = 380; addUpdateListener { bg?.alpha = it.animatedValue as Int }; start()
            }
            icon.animate().translationX(dx).translationY(dy).scaleX(scale).scaleY(scale)
                .setDuration(520).setInterpolator(android.view.animation.DecelerateInterpolator(1.6f))
                .withEndAction { lockIcon.alpha = 1f; v.remove(); lockIcon.play() }.start()
        }, wait)
    }

    override fun onDestroy() { unregisterReceiver(usbEvents); super.onDestroy() }

    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); setIntent(intent); whenUnlocked { handle(intent) } }

    /** A drive was plugged in and the user chose this app: go straight to its passphrase prompt. */
    private fun handle(i: Intent?) {
        if (i?.action != UsbManager.ACTION_USB_DEVICE_ATTACHED) return
        // only a drive is opened this way
        i.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)?.takeIf { UsbBlockDevice.massStorageInterface(it) != null }?.let { openDrive(it) }
    }

    private val usbEvents = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            val d = i.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
            if (i.action == ACTION_USB_PERMISSION && d != null) {
                if (i.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) openDrive(d, pendingAction) else toast("USB access denied")
            }
            if (i.action == UsbManager.ACTION_USB_DEVICE_DETACHED && d != null) waitingOn.remove(d.deviceName)?.takeIf { it.isShowing }?.cancel()
            render()
        }
    }

    /** Unlock requests (volume chooser, passphrase) waiting on a drive, by USB device name: cancelled when it's unplugged. */
    private val waitingOn = HashMap<String, android.app.Dialog>()

    private fun track(source: String?, d: android.app.Dialog) { if (source != null) waitingOn[source] = d }   // a closed one is skipped at unplug

    private fun drives() = usb.deviceList.values.filter { UsbBlockDevice.massStorageInterface(it) != null && !Volumes.isOpen(it.deviceName) }

    /** What the drive calls itself over USB: the same for every stick of a model. */
    private fun usbName(d: UsbDevice) = listOfNotNull(d.manufacturerName, d.productName).joinToString(" ").ifBlank { "USB drive" }

    /** The serial number tells identical drives apart; Android only gives it out once the app has access to the drive. */
    private fun serial(d: UsbDevice) = if (usb.hasPermission(d)) runCatching { d.serialNumber }.getOrNull()?.takeIf { it.isNotBlank() } else null

    /** The label of the encrypted volume last unlocked on this drive, when it's one Cryptic Vaults knows; else its USB name. */
    private fun driveName(d: UsbDevice) = serial(d)?.let { prefs.driveLabel(it) } ?: usbName(d)

    private fun openDrive(d: UsbDevice, action: DriveAction = DriveAction.UNLOCK) {
        if (Volumes.isOpen(d.deviceName)) return
        if (!usb.hasPermission(d)) {
            pendingAction = action
            val pi = PendingIntent.getBroadcast(this, 0, Intent(ACTION_USB_PERMISSION).setPackage(packageName), PendingIntent.FLAG_MUTABLE)
            usb.requestPermission(d, pi); return
        }
        val name = driveName(d)
        val wait = AlertDialog.Builder(this).setTitle(name).setMessage("Reading the drive…").setCancelable(false).show()
        thread(name = "usb-open") {
            val result = runCatching {
                val dev = UsbBlockDevice.open(usb, d)
                try { dev to Partitions.findLuks(dev) } catch (e: Exception) { dev.close(); throw e }
            }
            runOnUiThread {
                wait.dismiss()
                result.onFailure { AppLog.e("open USB $name", it); toast("Can't read $name: ${it.message}") }
                result.onSuccess { (dev, found) ->
                    if (action == DriveAction.FORMAT) return@onSuccess maintenance.formatDrive(dev, name, d.deviceName)
                    if (action == DriveAction.WIPE) return@onSuccess maintenance.wipeDrive(dev, name)
                    if (action == DriveAction.DETAILS) { details.showDrive(dev, d, found); return@onSuccess }
                    if (action == DriveAction.EDIT) return@onSuccess when (found.size) {
                        0 -> { dev.close(); toast("No LUKS2 volume on $name to edit") }
                        else -> maintenance.editLocked(slice(dev, found[0]), name)
                    }
                    AppLog.i("USB $name: ${dev.size} bytes, block ${dev.sectorSize}, LUKS volumes ${found.map { it.name }}")
                    when (found.size) {
                        0 -> { dev.close(); toast("No LUKS2 volume on $name") }
                        1 -> askPassphrase(slice(dev, found[0]), name, d.deviceName)
                        else -> AlertDialog.Builder(this).setTitle("Which volume on $name?")
                            .setItems(found.map { "${it.name} (${Formatter.formatFileSize(this, it.size)})" }.toTypedArray()) { _, k ->
                                askPassphrase(slice(dev, found[k]), "$name — ${found[k].name}", d.deviceName)
                            }.setOnCancelListener { dev.close() }.show().also { track(d.deviceName, it) }
                    }
                }
            }
        }
    }

    private fun slice(dev: BlockDevice, p: Partitions.Found) = if (p.start == 0L && p.size == dev.size) dev else SliceBlockDevice(dev, p.start, p.size)

    private lateinit var lockIcon: LockIcon
    private lateinit var title: SheenText
    private lateinit var vaults: SheenText

    /** "Cryptic™" decodes; once it settles, "Vaults" fades in below with its own sheen. */
    private fun revealTitle() = title.reveal("Cryptic™") { fitVaults(); vaults.animate().alpha(1f).setDuration(600).start(); vaults.play() }

    /** Sizes "Vaults" to run from just right of the "p" in "Cryptic™" to the ™'s right edge. */
    private fun fitVaults() {
        val t = title.text; val tp = title.paint
        val start = android.text.Layout.getDesiredWidth(t, 0, t.indexOf('p') + 1, tp) + ui.dp(3)
        val target = android.text.Layout.getDesiredWidth(t, tp) - start
        vaults.setTextSize(android.util.TypedValue.COMPLEX_UNIT_PX, vaults.textSize * target / vaults.paint.measureText("Vaults"))
        (vaults.layoutParams as LinearLayout.LayoutParams).leftMargin = titleIndent + start.toInt(); vaults.requestLayout()
    }

    override fun onResume() { super.onResume(); Volumes.listeners.add(refresh); render() }
    override fun onPause() { super.onPause(); Volumes.listeners.remove(refresh) }

    private val ui by lazy { Ui(this) }

    /** Padlock that snaps shut and then sets off the sheen on "Cryptic™ Vaults"; gear for Settings. */
    /** Left edge of the title, past the padlock: "Vaults" and the tagline line up under it. */
    private val titleIndent by lazy { ui.dp(52 + 14) }

    private fun header() = ui.column().apply {
        clipChildren = false; clipToPadding = false   // the padlock's burst spills over the title
        setPadding(ui.dp(4), ui.dp(8), 0, ui.dp(8))
        title = SheenText(this@MainActivity).apply { text = "Cryptic™"; textSize = 34f; setSingleLine() }
        // a softer true italic (serif), so the product name reads apart from the family name
        vaults = SheenText(this@MainActivity).apply {
            text = "Vaults"; textSize = 22f; setSingleLine(); alpha = 0f
            typeface = android.graphics.Typeface.create("serif", android.graphics.Typeface.ITALIC); letterSpacing = 0.04f
        }
        lockIcon = LockIcon(this@MainActivity)
        // padlock, "Cryptic™" and the gear on one line; the rest sits below, under the title
        addView(LinearLayout(this@MainActivity).apply {
            clipChildren = false; clipToPadding = false; gravity = android.view.Gravity.CENTER_VERTICAL
            addView(lockIcon, LinearLayout.LayoutParams(ui.dp(52), ui.dp(52)))
            addView(title, LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = ui.dp(14) })
            addView(android.widget.ImageView(this@MainActivity).apply {
                setImageResource(R.drawable.ic_settings); imageTintList = android.content.res.ColorStateList.valueOf(getColor(R.color.text_muted))
                contentDescription = "Settings"; setPadding(ui.dp(10), ui.dp(10), ui.dp(10), ui.dp(10)); isClickable = true
                setOnClickListener { startActivity(Intent(this@MainActivity, SettingsActivity::class.java)) }
            }, LinearLayout.LayoutParams(ui.dp(44), ui.dp(44)))
        })
        addView(vaults, LinearLayout.LayoutParams(-2, -2).apply { leftMargin = titleIndent; topMargin = -ui.dp(8) })
        addView(TextView(this@MainActivity).apply {
            text = "LUKS2 removable disk & container encryption\nutility for Android"; textSize = 13f; setTextColor(getColor(R.color.text_muted))
        }, LinearLayout.LayoutParams(-2, -2).apply { leftMargin = titleIndent; topMargin = ui.dp(12) })
    }

    /** Sections appear only when they have something to show; every volume, drive and container gets a card. */
    private fun render() {
        content.removeAllViews()
        val vols = Volumes.all()
        // remember each unlocked drive's volume label under its serial number, for the next time it's plugged in
        for (v in vols) usb.deviceList[v.source]?.let { d ->
            val label = v.fs.label.ifEmpty { v.crypt.label }
            if (label.isNotEmpty()) serial(d)?.let { prefs.nameDrive(it, label) }
        }
        val ds = drives()
        if (vols.isNotEmpty()) { content.addView(ui.section("Unlocked")); vols.forEach { content.addView(volumeCard(it)) } }
        val usbInUse = vols.any { v -> v.source != null && usb.deviceList.values.any { it.deviceName == v.source } }
        if (ds.isNotEmpty() || !usbInUse) content.addView(ui.section("USB drives"))
        if (ds.isEmpty() && !usbInUse) content.addView(ui.empty("Plug in a USB drive. LUKS2 drives open here automatically."))
        for (d in ds) content.addView(ui.card().apply {
            addView(ui.item(R.drawable.ic_usb, driveName(d), usbName(d).takeIf { it != driveName(d) } ?: "USB drive"))
            addView(ui.row(ui.button("Unlock", Ui.Kind.PRIMARY) { openDrive(d) }, ui.button("Details") { openDrive(d, DriveAction.DETAILS) }))
            addView(ui.row(
                ui.button("Encrypt…") { openDrive(d, DriveAction.FORMAT) },
                ui.button("Edit…") { openDrive(d, DriveAction.EDIT) },
                ui.button("Wipe…", Ui.Kind.DANGER) { openDrive(d, DriveAction.WIPE) },
                top = 8,
            ))
        })
        content.addView(ui.section("Container files"))
        content.addView(ui.card().apply {
            addView(ui.item(R.drawable.ic_file_lock, "Open or create a container", "A LUKS2 volume stored as a file on the phone"))
            addView(ui.row(ui.button("Open…", Ui.Kind.PRIMARY) { pickContainer() }, ui.button("New…") { newContainer() }))
        })
        val mine = prefs.containers.filter { c -> !Volumes.isOpen(c.uri.toString()) }
        if (mine.isNotEmpty()) content.addView(ui.section("My containers"))
        for (c in mine) content.addView(ui.card().apply {
            addView(ui.item(R.drawable.ic_file_lock, c.name, "Encrypted container"))
            addView(ui.row(ui.button("Unlock", Ui.Kind.PRIMARY) { openContainer(c.uri) }, ui.button("Forget") { forget(c) }))
        })
    }

    private fun forget(c: Prefs.Container) {
        AlertDialog.Builder(this).setTitle("Forget ${c.name}?").setMessage("It's removed from this list only. The file itself stays where it is.")
            .setPositiveButton("Forget") { _, _ -> prefs.forget(c.uri); render() }.setNegativeButton("Cancel", null).show()
    }

    private fun volumeCard(v: Volumes.Volume) = ui.card().apply {
            val fs = v.fs
            val kind = "LUKS2 · ${fs.type}" + if (fs.readOnlyReason != null) " · read-only" else ""
            addView(ui.item(R.drawable.ic_lock_small, v.title, kind))
            if (v.closing) { addView(ui.note("Locking… wait before unplugging")); return@apply }
            addView(ui.usage(fs.totalBytes - fs.freeBytes, fs.totalBytes))
            addView(ui.note("${Formatter.formatFileSize(context, fs.freeBytes)} free of ${Formatter.formatFileSize(context, fs.totalBytes)}", top = 6))
            fs.readOnlyReason?.let { addView(ui.note("Read-only: $it", top = 4)) }
            addView(ui.row(ui.button("Open in Files", Ui.Kind.PRIMARY) { openInFiles(v) }, ui.button("Lock") { Volumes.lock(this@MainActivity, v.id) }))
            addView(ui.row(ui.button("Details") { details.showVolume(v) }, ui.button("Edit…") { maintenance.editVolume(v) }, top = 8))
    }

    private fun openInFiles(v: Volumes.Volume) {
        val uri = DocumentsContract.buildRootUri(VolumeProvider.AUTHORITY, v.id)
        val i = Intent(Intent.ACTION_VIEW).setDataAndType(uri, DocumentsContract.Root.MIME_TYPE_ITEM)
        // other apps (file managers, "save to" screens) also answer this intent: ask the system Files app by name
        packageManager.queryIntentActivities(i, 0).map { it.activityInfo.packageName }
            .firstOrNull { it.endsWith(".documentsui") }?.let { i.setPackage(it) }
        runCatching { startActivity(i) }.onFailure {
            AppLog.e("open Files app", it)
            Toast.makeText(this, "Open the Files app and pick \"${v.title}\" in its menu", Toast.LENGTH_LONG).show()
        }
    }

    fun refresh() = render()

    private fun newContainer() {
        startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
            .setType("application/octet-stream").putExtra(Intent.EXTRA_TITLE, "vault.luks")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION), REQ_NEW)
    }

    private fun pickContainer() {
        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION), REQ_CONTAINER)
    }

    @Deprecated("platform Activity result API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val uri = data?.data
        if (requestCode == REQ_CONTAINER && resultCode == RESULT_OK && uri != null) openContainer(uri)
        if (requestCode == REQ_NEW && resultCode == RESULT_OK && uri != null) maintenance.createContainer(uri, displayName(uri))
    }

    private fun displayName(uri: Uri): String = contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
        ?.use { if (it.moveToFirst()) it.getString(0) else null } ?: "container"

    private fun openContainer(uri: Uri) {
        val name = runCatching { displayName(uri) }.getOrElse { prefs.containers.firstOrNull { it.uri == uri }?.name ?: "container" }
        val dev = try {
            PfdBlockDevice(contentResolver.openFileDescriptor(uri, "rw") ?: error("no descriptor"))
        } catch (e: Exception) {
            AppLog.e("open container $name", e)
            toast(if (prefs.isRemembered(uri)) "Can't open $name: it was moved, deleted or its storage is gone. Forget it to remove it from the list."
                  else "Can't open $name read-write: ${e.message}")
            return
        }
        askPassphrase(dev, name, uri.toString(), rememberable = if (prefs.isRemembered(uri)) null else uri)
    }

    /**
     * Checks the header, asks for the passphrase and unlocks; used for container files and USB drives. A container
     * not yet remembered ([rememberable]) gets the "Remember this container" option.
     */
    fun askPassphrase(dev: BlockDevice, title: String, source: String? = null, rememberable: Uri? = null) {
        val ok = try { Luks2.isLuks(dev) } catch (e: Exception) { AppLog.e("read $title", e); false }
        if (!ok) { toast("$title is not a LUKS2 volume"); dev.close(); return }
        // with app lock on, a vault's passphrase can be saved: what unlocks the app releases it
        val uuid = if (prefs.appLock) runCatching { Luks2.readHeader(dev).uuid }.getOrDefault("") else ""
        if (saved.has(uuid)) return saved.load(uuid, title) { pass ->
            if (pass != null) unlock(dev, pass, title, source, uuid, fromSaved = true) else passphraseForm(dev, title, source, rememberable, uuid)
        }
        passphraseForm(dev, title, source, rememberable, uuid)
    }

    private val saved by lazy { SavedPass(this) }

    private fun passphraseForm(dev: BlockDevice, title: String, source: String?, rememberable: Uri?, uuid: String) {
        val f = Form(this, "Unlock $title").password("pw", "Passphrase")
        if (rememberable != null) f.check("remember", "Remember this container on this phone", true)
        if (uuid.isNotEmpty() && !saved.has(uuid) && saved.problem == null)
            f.check("save", "Save this passphrase on this phone, protected by ${saved.protection}", false)
        track(source, f.show("Unlock", onCancel = { dev.close() }, validate = { if (it.text["pw"].isNullOrEmpty()) "Enter the passphrase" else null }) { v ->
            if (rememberable != null && v.checks["remember"] == true) prefs.remember(rememberable, title)
            unlock(dev, v.text.getValue("pw").toByteArray(Charsets.UTF_8), title, source, uuid, save = v.checks["save"] == true)
        })
    }

    /** [save]: keep the passphrase for the vault [uuid] once it has opened it. [fromSaved]: it came from there. */
    private fun unlock(dev: BlockDevice, pass: ByteArray, title: String, source: String?, uuid: String = "", save: Boolean = false, fromSaved: Boolean = false) {
        val wait = AlertDialog.Builder(this).setTitle("Unlocking $title").setMessage("Deriving the key…").setCancelable(false).show()
        val keep = if (save) pass.copyOf() else null     // Volumes.unlock wipes pass
        thread(name = "unlock") {
            var retry = false
            val err = try { Volumes.unlock(this, dev, pass, title, source); null } catch (e: WrongPassphraseException) {
                retry = true
                if (fromSaved) "The saved passphrase no longer opens $title, so it was removed. Enter the current one." else "Wrong passphrase"
            } catch (e: Throwable) {
                AppLog.e("unlock $title", e); "Can't unlock $title: ${e.message ?: e.javaClass.simpleName}"
            }
            runOnUiThread {
                wait.dismiss()
                if (err != null) { toast(err); keep?.fill(0) }
                else if (keep != null) saved.confirmFirst({ toast(if (saved.save(uuid, title, keep)) "Passphrase saved for $title" else "The passphrase for $title could not be saved") }) { keep.fill(0) }
                if (retry && fromSaved) saved.forget(uuid)
                if (retry) askPassphrase(dev, title, source) else render()
            }
        }
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()

    companion object {
        private const val REQ_CONTAINER = 1
        private const val REQ_NEW = 2
        private const val ACTION_USB_PERMISSION = "me.nocke.cryptic.vaults.USB_PERMISSION"
    }
}
