package me.nocke.cryptic.vaults

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.content.pm.ServiceInfo

/** Keeps the process (and so the unlocked volumes) alive while any volume is unlocked. */
class VolumeService : Service() {
    override fun onBind(intent: Intent?) = null

    private val detached = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)?.let { Volumes.unplugged(ctx, it.deviceName) }
        }
    }

    // A Handler tick doesn't run while the phone is in deep sleep, so an idle vault then locks at the next
    // wake-up; an AlarmManager wake-up alarm if the lock has to land on time while asleep
    private val timer = android.os.Handler(android.os.Looper.getMainLooper())
    private val autoLock = object : Runnable {
        override fun run() {
            Prefs(this@VolumeService).autoLockMinutes.let { if (it > 0) Volumes.lockIdle(this@VolumeService, it) }
            timer.postDelayed(this, 15_000)
        }
    }

    override fun onCreate() {
        super.onCreate()
        registerReceiver(detached, IntentFilter(UsbManager.ACTION_USB_DEVICE_DETACHED), RECEIVER_NOT_EXPORTED)
        timer.postDelayed(autoLock, 15_000)
    }

    override fun onDestroy() { timer.removeCallbacks(autoLock); unregisterReceiver(detached); super.onDestroy() }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_LOCK_ALL) { Volumes.lockAll(this); return START_NOT_STICKY }
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Unlocked volumes", NotificationManager.IMPORTANCE_LOW))
        val n = Volumes.all().size
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val lock = PendingIntent.getService(this, 1, Intent(this, VolumeService::class.java).setAction(ACTION_LOCK_ALL), PendingIntent.FLAG_IMMUTABLE)
        val notif = Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_lock_small)
            .setColor(getColor(R.color.accent))
            .setContentTitle(if (n == 1) "1 volume unlocked" else "$n volumes unlocked")
            .setContentText("Lock before unplugging a drive")
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, "Lock all", lock).build())
            .setOngoing(true)
            .build()
        startForeground(1, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        return START_NOT_STICKY
    }

    companion object {
        const val CHANNEL = "volumes"
        const val ACTION_LOCK_ALL = "me.nocke.cryptic.vaults.LOCK_ALL"
    }
}
