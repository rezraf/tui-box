package domain

import "time"

type SubscriptionFormat string

const (
	SubscriptionFormatURIList SubscriptionFormat = "uri-list"
	SubscriptionFormatBase64  SubscriptionFormat = "base64"
	SubscriptionFormatClash   SubscriptionFormat = "clash"
	SubscriptionFormatSingBox SubscriptionFormat = "sing-box"
)

type Subscription struct {
	ID                     string             `json:"id"`
	Name                   string             `json:"name"`
	SecretRef              string             `json:"secret_ref"`
	Format                 SubscriptionFormat `json:"format"`
	RefreshIntervalSeconds int                `json:"refresh_interval_seconds"`
	LastRefresh            *time.Time         `json:"last_refresh,omitempty"`
	LastError              string             `json:"last_error,omitempty"`
	RefreshToken           string             `json:"refresh_token,omitempty"`
}
