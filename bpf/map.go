package bpf

type MapDAO struct {
	Objs *bpfObjects
}

func (dao *MapDAO) SetP2C(poolerPort uint32, clientPort uint32) error {
	return dao.Objs.P2c.Put(poolerPort, clientPort)
}

func (dao *MapDAO) SetC2P(clientPort uint32, poolerPort uint32) error {
	return dao.Objs.C2p.Put(clientPort, poolerPort)
}

func (dao *MapDAO) SetP2SSockmap(poolerPort uint32, fd uint32) error {
	return dao.Objs.P2sSockmap.Put(poolerPort, fd)
}

func (dao *MapDAO) SetC2PSockmap(clientPort uint32, fd uint32) error {
	return dao.Objs.C2pSockmap.Put(clientPort, fd)
}
