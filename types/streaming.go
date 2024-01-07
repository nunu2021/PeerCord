package types

// --------------------------

func (j JoinCallRequestMessage) NewEmpty() Message {
	return &JoinCallRequestMessage{}
}

func (j JoinCallRequestMessage) Name() string {
	return "joincallrequest"
}

func (j JoinCallRequestMessage) String() string {
	return "joincallrequest{}"
}

func (j JoinCallRequestMessage) HTML() string {
	return j.String()
}

// --------------------------

func (j JoinCallReplyMessage) NewEmpty() Message {
	return &JoinCallReplyMessage{}
}

func (j JoinCallReplyMessage) Name() string {
	return "joincallreply"
}

func (j JoinCallReplyMessage) String() string {
	return "joincallreply{}"
}

func (j JoinCallReplyMessage) HTML() string {
	return j.String()
}

// --------------------------

func (l LeaveCallMessage) NewEmpty() Message {
	return &LeaveCallMessage{}
}

func (l LeaveCallMessage) Name() string {
	return "leavecall"
}

func (l LeaveCallMessage) String() string {
	return "leavecall{}"
}

func (l LeaveCallMessage) HTML() string {
	return l.String()
}

// --------------------------

func (c CallDataMessage) NewEmpty() Message {
	return &CallDataMessage{}
}

func (c CallDataMessage) Name() string {
	return "calldata"
}

func (c CallDataMessage) String() string {
	return "calldata{}"
}

func (c CallDataMessage) HTML() string {
	return c.String()
}
