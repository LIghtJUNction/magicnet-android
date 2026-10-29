#!/system/bin/sh
# The root manager chooses the module ID before this file is evaluated.
SKIPUNZIP=1
umask 077

mn_locale="$(getprop persist.sys.locale 2>/dev/null)"
case "$mn_locale" in zh*) mn_lang=zh;; ru*) mn_lang=ru;; ja*) mn_lang=ja;; ko*) mn_lang=ko;; *) mn_lang=en;; esac
mn_message() {
  case "$mn_lang:$1" in
    zh:begin) ui_print '- MagicNet：正在核验组件与迁移配置';;
    ru:begin) ui_print '- MagicNet: проверка компонентов и перенос настроек';;
    ja:begin) ui_print '- MagicNet: コンポーネント検証と設定の移行';;
    ko:begin) ui_print '- MagicNet: 구성 요소 확인 및 설정 이전';;
    en:begin) ui_print '- MagicNet: verifying components and migrating configuration';;
    zh:done) ui_print '- 安装已验证。重启后打开 WebUI 配置订阅；不会自动重启。';;
    ru:done) ui_print '- Установка проверена. После перезагрузки откройте WebUI. Автоперезагрузки нет.';;
    ja:done) ui_print '- インストールを検証しました。再起動後に WebUI を開いてください。自動再起動しません。';;
    ko:done) ui_print '- 설치가 확인되었습니다. 재부팅 후 WebUI를 여세요. 자동 재부팅하지 않습니다.';;
    en:done) ui_print '- Installation verified. Reboot, then open WebUI. No automatic reboot.';;
  esac
}

mn_arch="${ARCH:-$(getprop ro.product.cpu.abi 2>/dev/null)}"
case "$mn_arch" in arm64|arm64-v8a|aarch64) ;; *) abort '! architecture.unsupported';; esac
[ -n "${MODPATH:-}" ] && [ -n "${ZIPFILE:-}" ] || abort '! install.arguments'
case "$MODPATH" in /data/adb/modules/MagicNet|/data/adb/modules_update/MagicNet) ;; *) abort '! install.untrusted_root';; esac
mn_message begin
for mn_directory in /data /data/adb /data/adb/modules /data/adb/modules_update "$MODPATH" "$MODPATH/bin"; do
  [ ! -L "$mn_directory" ] || abort '! install.link_rejected'
done
mkdir -p "$MODPATH/bin" || abort '! install.mkdir_failed'
# Only the immutable bootstrap executable is extracted before ZIP validation.
mn_bootstrap="$MODPATH/bin/.magicnet-installer-bootstrap-$$"
mn_bootstrap_created=0
mn_abort() { [ "$mn_bootstrap_created" = 0 ] || rm -f "$mn_bootstrap"; abort "$1"; }
(set -C; : > "$mn_bootstrap") || mn_abort '! install.bootstrap_collision'
mn_bootstrap_created=1
unzip -p "$ZIPFILE" bin/magicnet-installer > "$mn_bootstrap" || mn_abort '! install.bootstrap_missing'
chmod 0700 "$mn_bootstrap" || mn_abort '! install.permissions_failed'
"$mn_bootstrap" verify "$ZIPFILE" || mn_abort '! install.archive_rejected'
if [ -n "${MAGICNET_COMPONENTS_CACHE:-}" ]; then
  "$mn_bootstrap" install --root "$MODPATH" --old /data/adb/modules/MagicNet --archive "$ZIPFILE" --cache-dir "$MAGICNET_COMPONENTS_CACHE" || mn_abort '! install.recovery_required'
else
  "$mn_bootstrap" install --root "$MODPATH" --old /data/adb/modules/MagicNet --archive "$ZIPFILE" || mn_abort '! install.recovery_required'
fi
"$mn_bootstrap" verify-installed "$MODPATH" || mn_abort '! install.verification_failed'
"$MODPATH/bin/magicnet-cli" __install || mn_abort '! install.configuration_failed'
rm -f "$mn_bootstrap"
mn_message done
