package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
)

type SendAlgorithm interface {
	TimeUntilSend(now time.Time, bytesInFlight protocol.ByteCount) time.Duration
	OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) bool
	GetCongestionWindow() protocol.ByteCount
	OnCongestionEvent(rttUpdated bool, bytesInFlight protocol.ByteCount, ackedPackets PacketVector, lostPackets PacketVector)
	SetNumEmulatedConnections(n int)
	OnRetransmissionTimeout(packetsRetransmitted bool)
	OnConnectionMigration()
	RetransmissionDelay() time.Duration

	// Experiments
	SetSlowStartLargeReduction(enabled bool)
}

type SendAlgorithmWithDebugInfo interface {
	SendAlgorithm
	BandwidthEstimate() Bandwidth

	// Stuff only used in testing
	// TODO: Maybe make CubicSender public and typeassert in tests?

	HybridSlowStart() *HybridSlowStart
	SlowstartThreshold() protocol.PacketNumber
	RenoBeta() float32
	InRecovery() bool
}
