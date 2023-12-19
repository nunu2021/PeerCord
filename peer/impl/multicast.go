package impl

import (
	"go.dedis.ch/cs438/transport"
)

func (n *node) NaiveMulticast(msg transport.Message, recipients map[string]struct{}) error {
	for dest := range recipients {
		err := n.Unicast(dest, msg)
		if err != nil {
			n.logger.Error().Err(err).Msg("can't unicast message")
			return err
		}
	}

	return nil
}

func (n *node) Multicast(msg transport.Message, recipients map[string]struct{}) error {
	/*multicastMsg := types.MulticastMessage{
		Recipients: recipients,
		Msg:        &msg,
	}*/

	return n.NaiveMulticast(msg, recipients)
}
