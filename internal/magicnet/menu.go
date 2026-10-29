package magicnet

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

var menuText = map[string][2]string{
	"en": {"MagicNet\n1. Health check\n2. Status\n3. Start\n4. Stop\n5. Refresh subscriptions\nEnter: exit", "Connections may be interrupted. Type YES to continue (default cancel): "},
	"zh": {"MagicNet\n1. 健康检查\n2. 状态\n3. 启动\n4. 停止\n5. 更新订阅\n直接回车退出", "此操作可能中断连接。输入 YES 继续（默认取消）："},
	"ru": {"MagicNet\n1. Проверка состояния\n2. Статус\n3. Запустить\n4. Остановить\n5. Обновить подписки\nEnter: выход", "Возможно прерывание соединений. Введите YES для продолжения (по умолчанию — отмена): "},
	"ja": {"MagicNet\n1. 正常性確認\n2. 状態\n3. 起動\n4. 停止\n5. 購読を更新\nEnter：終了", "接続が中断する場合があります。続行するには YES を入力（既定は取消）："},
	"ko": {"MagicNet\n1. 상태 검사\n2. 상태\n3. 시작\n4. 중지\n5. 구독 업데이트\nEnter: 종료", "연결이 중단될 수 있습니다. 계속하려면 YES 입력(기본값은 취소): "},
}

func (a *App) menu(ctx context.Context) (M, error) {
	if os.Getenv("MAGICNET_NONINTERACTIVE") == "1" {
		return a.ServiceStatus(ctx)
	}
	locale := os.Getenv("MAGICNET_LANGUAGE")
	if locale == "" && a.Platform == "android" {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		r, e := Run(c, a.Root, a.findTool("getprop"), []string{"persist.sys.locale"}, nil, 256)
		cancel()
		if e == nil {
			locale = strings.TrimSpace(string(r.Stdout))
		}
	}
	if locale == "" {
		locale = os.Getenv("LANG")
	}
	lang := "en"
	if len(locale) >= 2 {
		if _, ok := menuText[locale[:2]]; ok {
			lang = locale[:2]
		}
	}
	t := menuText[lang]
	fmt.Fprintln(os.Stderr, t[0])
	var choice string
	if _, e := fmt.Fscanln(os.Stdin, &choice); e != nil {
		return M{"cancelled": true}, nil
	}
	switch choice {
	case "1":
		return a.health(ctx)
	case "2":
		return a.ServiceStatus(ctx)
	case "3":
		return a.serviceAction(ctx, "start")
	case "4", "5":
		fmt.Fprint(os.Stderr, t[1])
		var answer string
		fmt.Fscanln(os.Stdin, &answer)
		if answer != "YES" {
			return M{"cancelled": true}, nil
		}
		if choice == "4" {
			return a.serviceAction(ctx, "stop")
		}
		return a.RefreshSubscriptions(ctx)
	}
	return nil, E("menu.selection_invalid", "Unknown menu selection.")
}
