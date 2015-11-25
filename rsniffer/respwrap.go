package rsniffer

import (
	"errors"
	"github.com/xiam/resp"
)

const (
	RecordCmdOnly = iota
	RecordParams
	RecordReply
)

const (
	KeyHit = iota
	KeyMiss
	KeyError
)

const (
	RedisCmdRead = iota
	RedisCmdWrite
	RedisCmdReadWrite
	RedisCmdFunc
)

var RedisCmds map[string]int = map[string]int{
	"GET": RedisCmdRead,
	//"GETBIT":   RedisCmdRead,
	//"GETRANGE": RedisCmdRead,
	//"HGET":     RedisCmdRead,
	//"HGETALL":  RedisCmdRead,
	//"HLEN":     RedisCmdRead,
	//"HMGET":    RedisCmdRead,
	//"HSTRLEN":  RedisCmdRead,
	//"LINDEX":   RedisCmdRead,
	//"LLEN":     RedisCmdRead,
	//"LRANGE":   RedisCmdRead,
	"MGET": RedisCmdRead,
}

var MsgTypeMapping = map[byte]string{
	resp.ArrayHeader:   "Array",
	resp.BulkHeader:    "Bulk",
	resp.ErrorHeader:   "Error",
	resp.IntegerHeader: "Integer",
	resp.StringHeader:  "String",
}

type Command struct {
	Args []string
}

func NewCommand(args ...string) (*Command, error) {
	if len(args) == 0 {
		return nil, errors.New("empty args for command")
	}
	return &Command{Args: args}, nil
}

func (c *Command) Name() string {
	return c.Args[0]
}

type RespData struct {
	Msg *resp.Message
}

func (rd *RespData) MsgType() string {
	return MsgTypeMapping[rd.Msg.Type]
}

func (rd *RespData) IsString() bool {
	return rd.Msg.Type == resp.StringHeader
}

func (rd *RespData) IsError() bool {
	return rd.Msg.Type == resp.ErrorHeader
}

func (rd *RespData) IsInteger() bool {
	return rd.Msg.Type == resp.IntegerHeader
}

func (rd *RespData) IsBulk() bool {
	return rd.Msg.Type == resp.BulkHeader
}

func (rd *RespData) IsArray() bool {
	return rd.Msg.Type == resp.ArrayHeader
}

func (rd *RespData) GetCommand() (*Command, error) {
	if !rd.IsArray() {
		return nil, errors.New("not resp array type")
	}
	args := make([]string, len(rd.Msg.Array))
	for idx, arg := range rd.Msg.Array {
		args[idx] = string(arg.Bytes)
	}
	return NewCommand(args...)
}
