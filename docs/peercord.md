# Peer Cord

## Implementation

Below some of the APIs and implementation details will be written both for external understanding of the project and for internal use amongst group members

### Calling API
---

The first step in setting up a PeerCord call is dialing the other peer. This is done using the  `DialPeer(peer string)` node function. This will send a `DialMsg` to the other user, at which point the peer will be able to respond to the dial if it likes. If it would like to pick up the call (This is determined in the `PromptDial(caller)` function), it will respond in turn with a `DialMsg` with the corresponding call ID.

Within these `DialMsg` is also embedded the public identity and public key of both peers. These are saved for future use during the call.

The `peerCord` struct in the `node` stores some of the details pertaining to this call interaction. Most of the data is stored within the `DialingData`. This includes the dial state which can be one of `Idle`, `Dialing` and `Calling`. Once the peer enters the `Calling` state, it will stay in this state until the full call terminates (I.e. if the call expands to a group call, the peer will stay in the calling staying). This means the user can only be in one call at a time and it will not be dialed while it is in a call (Line busy).

Of note, the person who initiates the call becomes the call leader (I.e. it flags to itself it is the leader and the receiving node will know it is a follower). This leadership is later expanded to include DH key exchange leadership if the call expands to a group call.

### Voting
---

The voting, mostly happening in `voting.go` is an async majority based manner. Voting is done using the `GroupCallVotePkt` messages. To initiate a vote, a user simply broadcasts a group encrypted packet containing the voting message.

When a peer receives one of these messages, it will check if it has seen this vote ID before. If it hasnt't seen it, a local vote is initiated. The peer will then cast its own vote by sending a vote packet as well. Finally, in either case it will then check if the vote ID has reached a consensus based on the amount of agreers and the number of nodes in the call. Note, if it receives duplicate messages from one node, it will ignore the newer messages and only process the oldest vote.

When a majority is reached, each node can take a local action (I.e. add or remove a peer from it's local copy of the call list) and the leader will take the global action of either dialing the other node or of removing the node and in both cases starting a DH round.

### Entering a Group Call
---

Once a decision is made to enter a group call, the leader of the call will send a dial message to the desired node. Attached will be a list of nodes which will have a list of the current call members. This will be used to seed the user with who they need to communicate with for the group call.