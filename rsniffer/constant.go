package rsniffer

import (
	"errors"
)

const (
	AnalyzeCmd     = "cmd"
	AnalyzeCmdType = "type"
	AnalyzeParams  = "params"
	AnalyzeReply   = "reply"
	AnalyzeRequest = "request"
	AnalyzeStat    = "stat"
)

var (
	RedSessionCloseErr = errors.New("redis session closed")
)

const (
	RecordCmdOnly = iota + 1
	RecordParams
	RecordReply
	RecordRequest
)

const (
	KeyHit = iota + 1
	KeyMiss
	KeyError
)

const (
	RedisCmdRead = iota + 1
	RedisCmdWrite
	RedisCmdFunc
)
