#!/bin/sh
# Runs inside the vectors container (see vectors.sh). Test passphrase for every image: test-pass
set -eu
PASS=test-pass
cd /v/out

manifest() {  # $1 mount point -> sorted "type size sha256 path" lines
    (cd "$1" && find . -mindepth 1 \( -type d -o -type f \) | LC_ALL=C sort | while read -r p; do
        if [ -d "$p" ]; then echo "d 0 - $p"; else echo "f $(stat -c %s "$p") $(sha256sum "$p" | cut -d' ' -f1) $p"; fi
    done)
}

populate() {  # $1 mount point: a fixed tree covering the cases the driver must handle
    m=$1
    printf 'hello exfat\n' > "$m/hello.txt"
    : > "$m/empty.bin"
    mkdir -p "$m/dir/sub"
    head -c 300000 /dev/urandom > "$m/dir/sub/random-300k.bin"
    printf 'unicode\n' > "$m/dir/Ünïcödé name with spaces and a fairly long tail to need several name entries.txt"
    # fragmented file: interleave two files, delete one, then grow the other
    for i in 1 2 3 4 5 6 7 8; do head -c 70000 /dev/urandom >> "$m/frag.bin"; head -c 70000 /dev/urandom >> "$m/gap.bin"; sync; done
    rm "$m/gap.bin"; head -c 200000 /dev/urandom >> "$m/frag.bin"
    for i in $(seq 1 40); do echo "$i" > "$m/dir/many-$i.txt"; done
}

populate_ext() {  # $1 mount point: what only ext4 has
    m=$1
    mkdir "$m/bigdir"; for i in $(seq 1 300); do echo "$i" > "$m/bigdir/entry-with-a-longish-name-$i"; done   # htree
    ln -s hello.txt "$m/link"; ln "$m/hello.txt" "$m/dir/hard"
    fallocate -l 200000 "$m/prealloc.bin" 2>/dev/null || head -c 200000 /dev/zero > "$m/prealloc.bin"; printf 'head' | dd of="$m/prealloc.bin" conv=notrunc status=none   # uninit extents
    truncate -s 1000000 "$m/sparse-ext.bin"; printf 'middle' | dd of="$m/sparse-ext.bin" bs=1 seek=500000 conv=notrunc status=none
    chown -R 1000:1000 "$m"
}

mkext() {  # $1 file, $2 size MiB, rest: mkfs.ext4 options (LUKS2 when $LUKS=1)
    f=$1; mib=$2; shift 2
    rm -f "$f"; truncate -s "${mib}M" "$f"
    if [ "${LUKS:-0}" = 1 ]; then
        printf %s "$PASS" | cryptsetup luksFormat -q --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file - "$f"
        printf %s "$PASS" | cryptsetup open --key-file - "$f" vec; dev=/dev/mapper/vec
    else dev=$(losetup -f --show "$f"); fi
    mkfs.ext4 -q -F "$@" "$dev"
    mount "$dev" /mnt/x; populate /mnt/x; populate_ext /mnt/x; manifest /mnt/x > "$f.manifest"; umount /mnt/x
    if [ "${LUKS:-0}" = 1 ]; then cryptsetup close vec; else losetup -d "$dev"; fi
}

mkdirty() {  # $1 file, rest: mkfs.ext4 options -> ext4 copied while mounted: committed journal not yet written home
    f=$1; shift
    rm -f "$f"; truncate -s 64M "$f"; dev=$(losetup -f --show "$f")
    mkfs.ext4 -q -F "$@" "$dev"
    mount -o commit=1 "$dev" /mnt/x; populate /mnt/x; populate_ext /mnt/x; sync
    # after the last sync: creates, deletes (revokes), a rename and a grown file live only in the log for ~30 s
    mkdir /mnt/x/late; for i in $(seq 1 50); do echo "late $i" > "/mnt/x/late/f$i"; done
    sync /mnt/x/late/*   # fsync: data written, metadata committed to the log only
    rm -r /mnt/x/bigdir /mnt/x/dir/many-1*.txt; mv /mnt/x/hello.txt /mnt/x/late/renamed.txt
    head -c 100000 /dev/urandom >> /mnt/x/frag.bin; chown -R 1000:1000 /mnt/x/late
    sleep 3; cp --sparse=always "$f" "$f.tmp"
    umount /mnt/x; losetup -d "$dev"; mv "$f.tmp" "$f"
    debugfs -R stats "$f" 2>/dev/null | grep -q needs_recovery || { echo "$f: not dirty" >&2; exit 3; }
    # the reference: what the kernel reads after replaying a copy (unsynced data is lost, as after a real unplug)
    cp --sparse=always "$f" "$f.ref"; dev=$(losetup -f --show "$f.ref")
    mount "$dev" /mnt/x; manifest /mnt/x > "$f.manifest"; umount /mnt/x; losetup -d "$dev"; rm "$f.ref"
}

mkplain() {  # $1 file $2 size MiB -> exFAT image with the tree
    rm -f "$1"; truncate -s "$2M" "$1"; mkfs.exfat -q -c 4K "$1" >/dev/null
    dev=$(losetup -f --show "$1")
    mount.exfat-fuse "$dev" /mnt/x; populate /mnt/x; manifest /mnt/x > "$1.manifest"; umount /mnt/x; losetup -d "$dev"
}

mkluks() {  # $1 file, rest: luksFormat options -> LUKS2 + exFAT image with the tree
    f=$1; shift
    rm -f "$f"; truncate -s 48M "$f"
    printf %s "$PASS" | cryptsetup luksFormat -q --type luks2 "$@" --key-file - "$f"
    printf %s "$PASS" | cryptsetup open --key-file - "$f" vec
    mkfs.exfat -q /dev/mapper/vec >/dev/null
    mount.exfat-fuse /dev/mapper/vec /mnt/x; populate /mnt/x; manifest /mnt/x > "$f.manifest"; umount /mnt/x
    cryptsetup luksDump --dump-json-metadata "$f" > "$f.json"
    cryptsetup close vec
}

case "${1:-}" in
make)
    mkdir -p /mnt/x
    mkplain plain.exfat.img 32
    # light KDF costs keep JVM tests fast; the format is the same as the defaults
    mkluks luks2-argon2id.img --pbkdf argon2id --pbkdf-memory 8192 --pbkdf-parallel 2 --pbkdf-force-iterations 4
    mkluks luks2-argon2i.img --pbkdf argon2i --pbkdf-memory 8192 --pbkdf-parallel 1 --pbkdf-force-iterations 4
    mkluks luks2-pbkdf2.img --pbkdf pbkdf2 --hash sha256 --pbkdf-force-iterations 1000 --sector-size 512
    mkluks luks2-4k.img --sector-size 4096 --pbkdf argon2id --pbkdf-memory 8192 --pbkdf-force-iterations 4
    # cryptsetup's own defaults (Argon2id up to 1 GiB): what a drive formatted on a Linux desktop has; device tests only
    mkluks luks2-default.img
    # what cryptsetup picks on a desktop with plenty of RAM: Argon2id 1 GiB, 4 lanes
    mkluks luks2-1g.img --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --pbkdf-force-iterations 4
    # partitioned drives: the pbkdf2 volume as partition 1 (at 1 MiB) of a GPT and of an MBR disk
    for t in gpt dos; do
        rm -f $t-disk.img; truncate -s 64M $t-disk.img
        echo 'start=2048, size=110592' | sfdisk -q --label $t $t-disk.img
        dd if=luks2-pbkdf2.img of=$t-disk.img bs=1M seek=1 conv=notrunc status=none
    done
    mkext ext4.img 64 -b 4096
    mkext ext4-1k-nocsum.img 64 -b 1024 -O ^metadata_csum
    mkext ext3.img 64 -t ext3
    LUKS=1 mkext luks2-ext4.img 80
    sh "$0" dirty
    cryptsetup --version > tools.version; mkfs.exfat -V 2>&1 | head -1 >> tools.version
    ls -l ;;
dirty)
    # ext4 left mounted, as by an unplug: Cryptic Vaults must replay the journal (csum v3 64-bit log; no-checksum 32-bit log)
    mkdir -p /mnt/x
    mkdirty dirty-ext4.img -b 4096
    mkdirty dirty-ext4-1k.img -b 1024 -O ^metadata_csum,^64bit
    ls -l dirty-* ;;
big)
    # a 2 TB sparse LUKS2 + ext4 drive like a desktop-made SSD (only metadata is real data); device tests only
    f=big-ext4.img; rm -f "$f"; truncate -s 2000G "$f"
    printf %s "$PASS" | cryptsetup luksFormat -q --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file - "$f"
    printf %s "$PASS" | cryptsetup open --key-file - "$f" vec
    mkfs.ext4 -q -F -E lazy_itable_init=1,lazy_journal_init=1 /dev/mapper/vec
    mkdir -p /mnt/x; mount /dev/mapper/vec /mnt/x; populate /mnt/x; head -c 50000000 /dev/urandom > /mnt/x/fifty-mb.bin; chown -R 1000:1000 /mnt/x; umount /mnt/x
    cryptsetup close vec; ls -ls "$f" ;;
check)
    # IMG may be partitioned (GPT/MBR: partition 1 is checked); with PASS the volume is LUKS2. Prints the manifest plus
    # PTABLE / PARTLABEL / LUKSLABEL / FSLABEL lines. A wrong PASS exits 2.
    img=$2; mkdir -p /mnt/x
    loop=$(losetup -f --show "/v/out/$img"); target=$loop; ploop=
    pt=$(blkid -p -o value -s PTTYPE "$loop" 2>/dev/null || true)
    if [ -n "$pt" ]; then
        # no udev in the container, so no partition nodes: map partition 1 with a second loop device
        set -- "$@"; read -r pstart psize <<EOF2
$(partx -g -o START,SECTORS -n 1 "$loop")
EOF2
        ploop=$(losetup -f --show --offset $((pstart * 512)) --sizelimit $((psize * 512)) "/v/out/$img"); target=$ploop
        echo "PTABLE=$pt"; echo "PARTLABEL=$(sfdisk --part-label "$loop" 1 2>/dev/null)"
        sfdisk --verify "$loop" >/dev/null 2>&1 || { echo "sfdisk --verify failed"; sfdisk --verify "$loop"; losetup -d "$ploop" "$loop"; exit 5; }
    fi
    if [ $# -ge 3 ]; then
        echo "LUKSLABEL=$(cryptsetup luksDump "$target" | sed -n 's/^Label:[[:space:]]*//p')"
        printf %s "$3" | cryptsetup open --key-file - "$target" chk || { [ -n "$ploop" ] && losetup -d "$ploop"; losetup -d "$loop"; exit 2; }
        dev=/dev/mapper/chk
    else dev=$target; fi
    echo "FSLABEL=$(blkid -o value -s LABEL "$dev")"
    if [ "$(blkid -o value -s TYPE "$dev")" = exfat ]; then
        rc=0; fsck.exfat -n "$dev" || rc=$?
        mount.exfat-fuse "$dev" /mnt/x && manifest /mnt/x && umount /mnt/x
    else
        # -n can exit 0 after declining fixes: any declined fix counts as a failure
        rc=0; e2fsck -fn "$dev" > /tmp/fsck.out 2>&1 || rc=$?; cat /tmp/fsck.out
        if grep -qE 'Fix\? no|IGNORED|should be|Clear\? no|Optimize\? no|Salvage\? no|Relocate\? no' /tmp/fsck.out; then rc=4; fi
        mount -o ro "$dev" /mnt/x && manifest /mnt/x && umount /mnt/x
        # then the kernel writes on top of what we wrote, and e2fsck must still be clean
        mount "$dev" /mnt/x && head -c 3000000 /dev/urandom > /mnt/x/kernel-wrote.bin && mkdir -p /mnt/x/kdir && cp /mnt/x/kernel-wrote.bin /mnt/x/kdir/ && rm -f /mnt/x/kernel-wrote.bin && umount /mnt/x
        e2fsck -fn "$dev" > /tmp/fsck2.out 2>&1 || rc=$?
        if grep -qE 'Fix\? no|IGNORED|should be|Clear\? no' /tmp/fsck2.out; then cat /tmp/fsck2.out; rc=4; fi
    fi
    if [ $# -ge 3 ]; then cryptsetup close chk; fi
    [ -n "$ploop" ] && losetup -d "$ploop"; losetup -d "$loop"
    exit $rc ;;
*) echo "usage: vectors.sh make | check IMG [PASS]" >&2; exit 2 ;;
esac
