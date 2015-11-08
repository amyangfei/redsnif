package rsniffer

import (
	"errors"
	"github.com/xiam/resp"
)

type Command struct {
	Args []string
}

func NewCommand(args ...string) (*Command, error) {
	if len(args) == 0 {
		return nil, errors.New("empty args for command")
	}
	return &Command{Args: args}, nil
}

type RespData struct {
	msg *resp.Message
}

func (rd *RespData) IsString() bool {
	return rd.msg.Type == resp.StringHeader
}

func (rd *RespData) IsError() bool {
	return rd.msg.Type == resp.ErrorHeader
}

func (rd *RespData) IsInteger() bool {
	return rd.msg.Type == resp.IntegerHeader
}

func (rd *RespData) IsBulk() bool {
	return rd.msg.Type == resp.BulkHeader
}

func (rd *RespData) IsArray() bool {
	return rd.msg.Type == resp.ArrayHeader
}

func (rd *RespData) GetCommand() (*Command, error) {
	if !rd.IsArray() {
		return nil, errors.New("not resp array type")
	}
	args := make([]string, len(rd.msg.Array))
	for idx, arg := range rd.msg.Array {
		args[idx] = string(arg.Bytes)
	}
	return NewCommand(args...)
}
