package notify

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
)

var (
	slackApi *slack.Client
)

// NewSlack create slack
func SlackInit(token string) {
	if len(token) == 0 {
		log.Infof("no slack token")
		return
	}
	log.Infof("slack token: %v", token)
	slackApi = slack.New(token)
}

func SlackMessagePush(body string) {
	slackChan := os.Getenv("SLACK_CHANNEL")
	if slackApi == nil || len(slackChan) == 0 {
		return
	}
	slackApi.PostMessage(slackChan, slack.MsgOptionText(body, false))
}

func SlackAlarmMessagePush(body string) {
	slackChan := os.Getenv("SLACK_CHANNEL_ALARM")
	nodeName := os.Getenv("NODE_NAME")
	if slackApi == nil || len(slackChan) == 0 {
		return
	}
	body = fmt.Sprintf("<!channel> %s : %s", nodeName, body)
	slackApi.PostMessage(slackChan, slack.MsgOptionText(body, false))
}
