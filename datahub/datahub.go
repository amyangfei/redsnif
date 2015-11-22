package datahub

import ()

const (
	HUB_ZMQ_PUBLISHER = iota + 1
	HUB_LOG_RECORDER
)

type DataHub interface {
	Run() error
}

type HubConfig struct {
	HubType    int
	Subscriber interface{}
}
