#!/system/bin/sh
MODDIR="${0%/*}"
case "$MODDIR" in /data/adb/modules/MagicNet) ;; *) exit 1;; esac
CLI="$MODDIR/bin/magicnet-cli"
if [ "${MAGICNET_NONINTERACTIVE:-0}" = 1 ]; then exec "$CLI" --json service status; fi
if [ -t 0 ]; then exec "$CLI" menu; fi

mn_locale="$(getprop persist.sys.locale 2>/dev/null)"
case "$mn_locale" in zh*) mn_lang=zh;; ru*) mn_lang=ru;; ja*) mn_lang=ja;; ko*) mn_lang=ko;; *) mn_lang=en;; esac
case "$mn_lang" in
  zh) mn_hint='音量减：选择 · 音量加：确认'; mn_labels='健康检查|状态|启动|停止|更新订阅|退出'; mn_confirm='可能中断连接。选择后确认，默认取消。'; mn_cancel='取消'; mn_accept='确认执行';;
  ru) mn_hint='Громкость −: выбор · Громкость +: подтвердить'; mn_labels='Проверка состояния|Статус|Запустить|Остановить|Обновить подписки|Выход'; mn_confirm='Возможно прерывание связи. По умолчанию — отмена.'; mn_cancel='Отмена'; mn_accept='Выполнить';;
  ja) mn_hint='音量−：選択 · 音量＋：決定'; mn_labels='正常性確認|状態|起動|停止|購読を更新|終了'; mn_confirm='接続が中断する場合があります。既定は取消です。'; mn_cancel='取消'; mn_accept='実行を確認';;
  ko) mn_hint='볼륨 −: 선택 · 볼륨 +: 확인'; mn_labels='상태 검사|상태|시작|중지|구독 업데이트|종료'; mn_confirm='연결이 중단될 수 있습니다. 기본값은 취소입니다.'; mn_cancel='취소'; mn_accept='실행 확인';;
  *) mn_hint='Volume down: select · Volume up: confirm'; mn_labels='Health check|Status|Start|Stop|Update subscriptions|Exit'; mn_confirm='Connections may be interrupted. Cancellation is selected by default.'; mn_cancel='Cancel'; mn_accept='Confirm action';;
esac
printf '%s\n' 'MagicNet' "$mn_hint"
mn_key() {
  # getevent is bounded; a missing volume key or manager pipe never blocks forever.
  mn_event="$(timeout 30 getevent -qlc 1 2>/dev/null)" || return 1
  case "$mn_event" in *KEY_VOLUMEDOWN*DOWN*|*0001*0072*00000001*) return 2;; *KEY_VOLUMEUP*DOWN*|*0001*0073*00000001*) return 3;; *) return 0;; esac
}
mn_confirmation() {
  mn_choice=0
  mn_confirm_count=0
  printf '%s\n' "$mn_confirm" "$mn_hint"
  while [ "$mn_confirm_count" -lt 20 ]; do
    if [ "$mn_choice" = 0 ]; then printf '> %s\n' "$mn_cancel"; else printf '> %s\n' "$mn_accept"; fi
    mn_key; mn_confirm_key=$?; mn_confirm_count=$((mn_confirm_count + 1))
    case "$mn_confirm_key" in
      1) return 1;;
      2) mn_choice=$((1 - mn_choice));;
      3) [ "$mn_choice" = 1 ]; return "$?";;
    esac
  done
  return 1
}
mn_index=1
mn_count=0
while [ "$mn_count" -lt 180 ]; do
  mn_label="$(printf '%s' "$mn_labels" | cut -d '|' -f "$mn_index")"
  printf '> %s\n' "$mn_label"
  mn_key; mn_result=$?; mn_count=$((mn_count + 1))
  case "$mn_result" in
    1) exit 0;;
    2) mn_index=$((mn_index % 6 + 1));;
    3)
      case "$mn_index" in
        1) exec "$CLI" health;;
        2) exec "$CLI" --json service status;;
        3) exec "$CLI" service start;;
        4|5)
          mn_confirmation || exit 0
          if [ "$mn_index" = 4 ]; then exec "$CLI" service stop; else exec "$CLI" sub update-all; fi;;
        6) exit 0;;
      esac;;
  esac
done
exit 0
