#!/system/bin/sh
# Rescan an unchanged packages.list through KernelSU's normal signature check.
# Requires existing Root; never loads/unloads a module or grants another app Root.
set -eu
umask 077
EXPECTED_BOOT=${1:?expected boot ID required}
ACTION=${2:---repair}
PROBE=${0%/*}/manager_probe
TARGET=/data/system/packages.list
LOCK=/data/system/.mi18-ksu-manager-repair.lock
STAGE=/data/system/.mi18-ksu-manager-$$.pending
BACKUP=''; renamed=0; stage_inode=''; old_mode=''
fail() { echo "MANAGER_ERROR $*"; exit 1; }
sha() { sha256sum "$1" | cut -d ' ' -f 1; }
boot() { [ "$(cat /proc/sys/kernel/random/boot_id)" = "$EXPECTED_BOOT" ] || fail BOOT_CHANGED; }
appid() { "$PROBE" | sed -n 's/^manager_appid=//p'; }
[ "$(id -u)" = 0 ] || fail ROOT_REQUIRED
boot
[ "$(getprop ro.product.device)" = hongkong ] || fail UNSUPPORTED_DEVICE
grep -q '^kernelsu ' /proc/modules || fail MODULE_NOT_LOADED
[ -x "$PROBE" ] || fail PROBE_MISSING
uid=$(cmd package list packages --user 0 -U me.weishu.kernelsu | sed -n 's/^package:me\.weishu\.kernelsu uid:\([0-9]*\)$/\1/p')
case "$uid" in ''|*[!0-9]*) fail MANAGER_APP_NOT_INSTALLED;; esac
expected_appid=$((uid%100000))
before_appid=$(appid) || fail PROBE_FAILED
case "$before_appid" in ''|*[!0-9]*) fail PROBE_FAILED;; esac
echo "MANAGER_BEFORE appid=$before_appid expected=$expected_appid boot=$EXPECTED_BOOT"
case "$ACTION" in --check) echo "MANAGER_CHECK appid=$before_appid expected=$expected_appid"; [ "$before_appid" = "$expected_appid" ]; exit $?;; --repair|--force-rescan) :;; *) fail BAD_ACTION;; esac
if [ "$before_appid" = "$expected_appid" ] && [ "$ACTION" != --force-rescan ]; then
  echo "MANAGER_OK already_recognized=1 appid=$before_appid"; exit 0
fi
[ -f "$TARGET" ] && [ ! -L "$TARGET" ] || fail BAD_PACKAGES_LIST
[ ! -e "$STAGE" ] && [ ! -L "$STAGE" ] || fail STALE_STAGE
mkdir -m 700 "$LOCK" 2>/dev/null || fail REPAIR_ALREADY_RUNNING
cleanup() {
  code=$?; trap - EXIT HUP INT TERM
  if [ "$renamed" = 1 ]; then
    # Do not change a replacement that PackageManager has written in the meantime.
    if [ "$(stat -c %i "$TARGET" 2>/dev/null)" = "$stage_inode" ] && [ "$(sha "$TARGET")" = "$before_sha" ]; then
      chmod "$old_mode" "$TARGET" || { echo MANAGER_ERROR MODE_RESTORE_FAILED; code=1; }
      if [ "$(stat -c '%u:%g:%a:%s' "$TARGET")" != "$metadata" ]; then echo MANAGER_ERROR METADATA_RESTORE_FAILED; code=1; fi
    else echo MANAGER_ERROR PACKAGES_CHANGED_AFTER_RENAME; code=1; fi
  fi
  rm -f "$STAGE"
  rmdir "$LOCK" 2>/dev/null || :
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
metadata=$(stat -c '%u:%g:%a:%s' "$TARGET")
old_mode=$(stat -c %a "$TARGET")
case "$metadata" in 1000:1032:640:*|1000:1032:644:*) :;; *) fail UNEXPECTED_METADATA;; esac
label=$(ls -Zd "$TARGET" | awk '{print $1}')
[ "$label" = u:object_r:packages_list_file:s0 ] || fail UNEXPECTED_LABEL
before_sha=$(sha "$TARGET"); source_inode=$(stat -c %i "$TARGET")
BACKUP=$(mktemp -d /data/local/tmp/mi18-ksu-manager-backup.XXXXXX) || fail BACKUP_FAILED
chmod 700 "$BACKUP"
printf '%s\n' "$EXPECTED_BOOT" > "$BACKUP/boot.id"
printf '%s\n' "$metadata" > "$BACKUP/original.stat"
printf '%s\n' "$before_sha" > "$BACKUP/original.sha256"
ls -lZ "$TARGET" > "$BACKUP/original.label"
cp -p "$TARGET" "$BACKUP/packages.list.original"
[ "$(sha "$BACKUP/packages.list.original")" = "$before_sha" ] || fail BACKUP_MISMATCH
cp -p "$TARGET" "$STAGE"
chcon u:object_r:packages_list_file:s0 "$STAGE"
[ "$(stat -c '%u:%g:%a:%s' "$STAGE")" = "$metadata" ] || fail STAGE_METADATA_MISMATCH
# Only the staged copy is temporarily readable. FS_MOVED_TO triggers a synchronous
# task-work scan before mv returns; cleanup then restores the exact original mode.
chmod 644 "$STAGE"
stage_inode=$(stat -c %i "$STAGE")
[ "$(sha "$STAGE")" = "$before_sha" ] || fail STAGE_HASH_MISMATCH
boot
[ "$(sha "$TARGET")" = "$before_sha" ] && [ "$(stat -c %i "$TARGET")" = "$source_inode" ] &&
  [ "$(stat -c '%u:%g:%a:%s' "$TARGET")" = "$metadata" ] || fail PACKAGES_CHANGED_RETRY
renamed=1
mv -f "$STAGE" "$TARGET"
boot
[ "$(sha "$TARGET")" = "$before_sha" ] || fail FINAL_HASH_MISMATCH
after_appid=$(appid) || fail PROBE_FAILED
echo "MANAGER_RESCAN appid=$after_appid expected=$expected_appid backup=$BACKUP content_sha256=$before_sha"
[ "$after_appid" = "$expected_appid" ] || fail NOT_RECOGNIZED_CHECK_OFFICIAL_MANAGER_SIGNATURE
# Restore permissions before reporting success or refreshing the manager app.
chmod "$old_mode" "$TARGET"
[ "$(stat -c '%u:%g:%a:%s' "$TARGET")" = "$metadata" ] || fail FINAL_METADATA_MISMATCH
echo "MANAGER_OK rescanned=1 appid=$after_appid restored_mode=$old_mode"
