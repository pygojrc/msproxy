package mspx

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

type Client struct {
	server *protocol.ServerSpec
	policy policy.Manager
}

type Server struct {
	users  []*protocol.MemoryUser
	policy policy.Manager
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config.Server == nil || config.Server.User == nil {
		return nil, errors.New("MSPX 缺少服务端账户")
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, err
	}
	if _, ok := server.User.Account.(*MemoryAccount); !ok {
		return nil, errors.New("MSPX 账户类型错误")
	}
	return &Client{server: server, policy: core.MustFromContext(ctx).GetFeature(policy.ManagerType()).(policy.Manager)}, nil
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	s := &Server{policy: core.MustFromContext(ctx).GetFeature(policy.ManagerType()).(policy.Manager)}
	if len(config.Users) == 0 {
		return nil, errors.New("MSPX 至少需要一个账户")
	}
	for _, configUser := range config.Users {
		user, err := configUser.ToMemoryUser()
		if err != nil {
			return nil, err
		}
		a, ok := user.Account.(*MemoryAccount)
		if !ok {
			return nil, errors.New("MSPX 账户类型错误")
		}
		for _, previous := range s.users {
			if a.Equals(previous.Account) {
				return nil, errors.New("MSPX psk 账户重复")
			}
		}
		s.users = append(s.users, user)
	}
	return s, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return errors.New("MSPX 缺少目标")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() || ob.Target.Network != net.Network_TCP {
		return errors.New("MSPX 首版仅支持 TCP，不支持 UDP/Mux")
	}
	ob.Name, ob.CanSpliceCopy = magic, 3
	conn, err := dialer.Dial(ctx, c.server.Destination)
	if err != nil {
		return err
	}
	defer conn.Close()
	// 握手和连接取消均来自 Xray 配置，不设置固定连接寿命。
	interrupt := context.AfterFunc(ctx, func() { conn.Close() })
	defer interrupt()
	p := c.policy.ForLevel(c.server.User.Level)
	if err := conn.SetDeadline(time.Now().Add(p.Timeouts.Handshake)); err != nil {
		return err
	}
	w, err := clientHandshake(conn, c.server.User.Account.(*MemoryAccount).Key)
	if err != nil {
		return err
	}
	if err := w.sendJSON(opConnect, target{Host: ob.Target.Address.String(), Port: uint16(ob.Target.Port)}); err != nil {
		return err
	}
	op, payload, err := w.receive()
	if err != nil {
		return err
	}
	var response result
	if op != opResult || json.Unmarshal(payload, &response) != nil {
		return errProtocol
	}
	if !response.OK {
		return errors.New("MSPX 请求被对端拒绝")
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	return relay(ctx, link, w, p)
}

func (s *Server) Network() []net.Network { return []net.Network{net.Network_TCP} }

func (s *Server) Process(parent context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if network != net.Network_TCP {
		return errors.New("MSPX 首版仅支持 TCP")
	}
	interrupt := context.AfterFunc(parent, func() { conn.Close() })
	defer interrupt()
	if err := conn.SetDeadline(time.Now().Add(s.policy.ForLevel(0).Timeouts.Handshake)); err != nil {
		return err
	}
	w, user, err := serverHandshake(conn, s.users)
	if err != nil {
		return err
	}
	op, payload, err := w.receive()
	if err != nil {
		return err
	}
	var request target
	if op != opConnect || json.Unmarshal(payload, &request) != nil || request.Host == "" || request.Port == 0 {
		return errProtocol
	}
	destination := net.TCPDestination(net.ParseAddress(request.Host), net.Port(request.Port))
	if !destination.IsValid() {
		return errProtocol
	}
	if inbound := session.InboundFromContext(parent); inbound != nil {
		inbound.Name, inbound.User, inbound.CanSpliceCopy = magic, user, 3
	}
	parent = log.ContextWithAccessMessage(parent, &log.AccessMessage{From: conn.RemoteAddr(), To: destination, Status: log.AccessAccepted, Email: user.Email})
	p := s.policy.ForLevel(user.Level)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	ctx = policy.ContextWithBufferPolicy(ctx, p.Buffer)
	uplinkReader, uplinkWriter := pipe.New(pipe.OptionsFromContext(ctx)...)
	downlinkReader, downlinkWriter := pipe.New(pipe.OptionsFromContext(ctx)...)
	clientLink := &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}
	routingLink := &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}
	// RESULT 只表示接受请求；目标连接和拒绝规则由 Dispatcher/出站处理。
	if err := w.sendJSON(opResult, result{OK: true}); err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	dispatched := make(chan error, 1)
	go func() { dispatched <- dispatcher.DispatchLink(ctx, destination, routingLink) }()
	relayErr := relay(ctx, clientLink, w, p)
	if relayErr != nil {
		cancel()
	}
	// 等出站排空管道后才取消路由上下文，避免 EOF 后丢失尾部上传。
	select {
	case dispatchErr := <-dispatched:
		if relayErr != nil {
			return relayErr
		}
		return dispatchErr
	case <-ctx.Done():
		common.Interrupt(uplinkReader)
		common.Interrupt(downlinkReader)
		<-dispatched
		if relayErr != nil {
			return relayErr
		}
		return ctx.Err()
	}
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
