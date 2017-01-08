package ackhandler

import (
	"errors"
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

var (
	// ErrDuplicateOrOutOfOrderAck occurs when a duplicate or an out-of-order ACK is received
	ErrDuplicateOrOutOfOrderAck = errors.New("SentPacketHandler: Duplicate or out-of-order ACK")
	// ErrTooManyTrackedSentPackets occurs when the sentPacketHandler has to keep track of too many packets
	ErrTooManyTrackedSentPackets = errors.New("Too many outstanding non-acked and non-retransmitted packets")
	// ErrAckForSkippedPacket occurs when the client sent an ACK for a packet number that we intentionally skipped
	ErrAckForSkippedPacket = qerr.Error(qerr.InvalidAckData, "Received an ACK for a skipped packet number")
	errAckForUnsentPacket  = qerr.Error(qerr.InvalidAckData, "Received ACK for an unsent package")
)

var errPacketNumberNotIncreasing = errors.New("Already sent a packet with a higher packet number.")

type sentPacketHandler struct {
	alarm    *utils.Timer
	rtoCount int

	lastSentPacketNumber protocol.PacketNumber
	lastSentPacketTime   time.Time
	skippedPackets       []protocol.PacketNumber

	largestAckedPacket *Packet

	largestReceivedPacketWithAck protocol.PacketNumber

	packetHistory      *PacketList
	stopWaitingManager stopWaitingManager

	retransmissionQueue []*Packet

	bytesInFlight protocol.ByteCount

	rttStats   *congestion.RTTStats
	congestion congestion.SendAlgorithm

	consecutiveRTOCount uint32
}

// NewSentPacketHandler creates a new sentPacketHandler
func NewSentPacketHandler(rttStats *congestion.RTTStats) SentPacketHandler {
	congestion := congestion.NewCubicSender(
		congestion.DefaultClock{},
		rttStats,
		false, /* don't use reno since chromium doesn't (why?) */
		protocol.InitialCongestionWindow,
		protocol.DefaultMaxCongestionWindow,
	)

	sph := sentPacketHandler{
		packetHistory:      NewPacketList(),
		stopWaitingManager: stopWaitingManager{},
		rttStats:           rttStats,
		alarm:              utils.NewTimer(365 * 24 * time.Hour),
		congestion:         congestion,
	}
	sph.runLossDetection()

	return &sph
}

func (h *sentPacketHandler) ackPacket(packetElement *PacketElement) {
	packet := &packetElement.Value
	h.bytesInFlight -= packet.Length
	h.packetHistory.Remove(packetElement)
}

// nackPacket NACKs a packet
// it returns true if a FastRetransmissions was triggered
func (h *sentPacketHandler) nackPacket(packetElement *PacketElement) bool {
	packet := &packetElement.Value

	packet.MissingReports++
	//
	// if packet.MissingReports > protocol.RetransmissionThreshold {
	// 	utils.Debugf("\tQueueing packet 0x%x for retransmission (fast)", packet.PacketNumber)
	// 	h.queuePacketForRetransmission(packetElement)
	// 	return true
	// }
	return false
}

func (h *sentPacketHandler) queuePacketForRetransmission(packetElement *PacketElement) {
	packet := &packetElement.Value
	h.bytesInFlight -= packet.Length
	h.retransmissionQueue = append(h.retransmissionQueue, packet)

	h.packetHistory.Remove(packetElement)

	// strictly speaking, this is only necessary for RTO retransmissions
	// this is because FastRetransmissions are triggered by missing ranges in ACKs, and then the LargestAcked will already be higher than the packet number of the retransmitted packet
	h.stopWaitingManager.QueuedRetransmissionForPacketNumber(packet.PacketNumber)
}

func (h *sentPacketHandler) largestInOrderAcked() protocol.PacketNumber {
	if f := h.packetHistory.Front(); f != nil {
		return f.Value.PacketNumber - 1
	}
	return h.largestAcked()
}

func (h *sentPacketHandler) largestAcked() protocol.PacketNumber {
	if h.largestAckedPacket != nil {
		return h.largestAckedPacket.PacketNumber
	}
	return 0
}

func (h *sentPacketHandler) SentPacket(packet *Packet) error {
	if packet.PacketNumber <= h.lastSentPacketNumber {
		return errPacketNumberNotIncreasing
	}

	for p := h.lastSentPacketNumber + 1; p < packet.PacketNumber; p++ {
		h.skippedPackets = append(h.skippedPackets, p)

		if len(h.skippedPackets) > protocol.MaxTrackedSkippedPackets {
			h.skippedPackets = h.skippedPackets[1:]
		}
	}

	now := time.Now()
	// h.lastSentPacketTime = now
	packet.SendTime = now
	if packet.Length == 0 {
		return errors.New("SentPacketHandler: packet cannot be empty")
	}
	h.bytesInFlight += packet.Length

	h.lastSentPacketNumber = packet.PacketNumber
	h.packetHistory.PushBack(*packet)

	isRetransmittable := packet.IsRetransmittable()

	h.congestion.OnPacketSent(
		now,
		h.BytesInFlight(),
		packet.PacketNumber,
		packet.Length,
		isRetransmittable,
	)

	if isRetransmittable {
		h.setLossDetectionAlarm()
	}
	return nil
}

func (h *sentPacketHandler) ReceivedAck(ackFrame *frames.AckFrame, withPacketNumber protocol.PacketNumber, rcvTime time.Time) error {
	if ackFrame.LargestAcked > h.lastSentPacketNumber {
		return errAckForUnsentPacket
	}

	// duplicate or out-of-order ACK
	if withPacketNumber <= h.largestReceivedPacketWithAck {
		return ErrDuplicateOrOutOfOrderAck
	}

	h.largestReceivedPacketWithAck = withPacketNumber

	// ignore repeated ACK (ACKs that don't have a higher LargestAcked than the last ACK)
	if ackFrame.LargestAcked <= h.largestInOrderAcked() {
		return nil
	}

	// check if it acks any packets that were skipped
	for _, p := range h.skippedPackets {
		if ackFrame.AcksPacket(p) {
			return ErrAckForSkippedPacket
		}
	}

	var ackedPackets congestion.PacketVector
	var lostPackets congestion.PacketVector
	ackRangeIndex := 0
	rttUpdated := false

	var el, elNext *PacketElement
	for el = h.packetHistory.Front(); el != nil; el = elNext {
		// determine the next list element right at the beginning, because el.Next() is not avaible anymore, when the list element is deleted (i.e. when the packet is ACKed)
		elNext = el.Next()
		packet := el.Value
		packetNumber := packet.PacketNumber

		// NACK packets below the LowestAcked
		if packetNumber < ackFrame.LowestAcked {
			retransmitted := h.nackPacket(el)
			if retransmitted {
				lostPackets = append(lostPackets, congestion.PacketInfo{Number: packetNumber, Length: packet.Length})
			}
			continue
		}

		// Update the RTT
		if packetNumber == ackFrame.LargestAcked {
			h.largestAckedPacket = &packet
			rttUpdated = true
			timeDelta := rcvTime.Sub(packet.SendTime)
			h.rttStats.UpdateRTT(timeDelta, ackFrame.DelayTime, rcvTime)
			if utils.Debug() {
				utils.Debugf("\tEstimated RTT: %dms", h.rttStats.SmoothedRTT()/time.Millisecond)
			}
		}

		if packetNumber > ackFrame.LargestAcked {
			break
		}

		if ackFrame.HasMissingRanges() {
			ackRange := ackFrame.AckRanges[len(ackFrame.AckRanges)-1-ackRangeIndex]

			for packetNumber > ackRange.LastPacketNumber && ackRangeIndex < len(ackFrame.AckRanges)-1 {
				ackRangeIndex++
				ackRange = ackFrame.AckRanges[len(ackFrame.AckRanges)-1-ackRangeIndex]
			}

			if packetNumber >= ackRange.FirstPacketNumber { // packet i contained in ACK range
				if packetNumber > ackRange.LastPacketNumber {
					return fmt.Errorf("BUG: ackhandler would have acked wrong packet 0x%x, while evaluating range 0x%x -> 0x%x", packetNumber, ackRange.FirstPacketNumber, ackRange.LastPacketNumber)
				}
				h.ackPacket(el)
				ackedPackets = append(ackedPackets, congestion.PacketInfo{Number: packetNumber, Length: packet.Length})
			} else {
				retransmitted := h.nackPacket(el)
				if retransmitted {
					lostPackets = append(lostPackets, congestion.PacketInfo{Number: packetNumber, Length: packet.Length})
				}
			}
		} else {
			h.ackPacket(el)
			ackedPackets = append(ackedPackets, congestion.PacketInfo{Number: packetNumber, Length: packet.Length})
		}
	}
	//
	// if rttUpdated {
	// 	// Reset counter if a new packet was acked
	// 	h.consecutiveRTOCount = 0
	// }

	h.garbageCollectSkippedPackets()

	h.stopWaitingManager.ReceivedAck(ackFrame)

	h.congestion.OnCongestionEvent(
		rttUpdated,
		h.BytesInFlight(),
		ackedPackets,
		lostPackets,
	)

	return nil
}

func (h *sentPacketHandler) DequeuePacketForRetransmission() *Packet {
	if len(h.retransmissionQueue) == 0 {
		return nil
	}

	if len(h.retransmissionQueue) > 0 {
		queueLen := len(h.retransmissionQueue)
		// packets are usually NACKed in descending order. So use the slice as a stack
		packet := h.retransmissionQueue[queueLen-1]
		h.retransmissionQueue = h.retransmissionQueue[:queueLen-1]
		return packet
	}

	return nil
}

func (h *sentPacketHandler) BytesInFlight() protocol.ByteCount {
	return h.bytesInFlight
}

func (h *sentPacketHandler) GetLeastUnacked() protocol.PacketNumber {
	return h.largestInOrderAcked() + 1
}

func (h *sentPacketHandler) GetStopWaitingFrame(force bool) *frames.StopWaitingFrame {
	return h.stopWaitingManager.GetStopWaitingFrame(force)
}

func (h *sentPacketHandler) SendingAllowed() bool {
	congestionLimited := h.BytesInFlight() > h.congestion.GetCongestionWindow()
	maxTrackedLimited := protocol.PacketNumber(len(h.retransmissionQueue)+h.packetHistory.Len()) >= protocol.MaxTrackedSentPackets
	if congestionLimited {
		utils.Debugf("congestion limited")
	}
	if maxTrackedLimited {
		utils.Debugf("maxTrackedLimited")
	}
	return !(congestionLimited || maxTrackedLimited)
}

func (h *sentPacketHandler) CheckForError() error {
	length := len(h.retransmissionQueue) + h.packetHistory.Len()
	if protocol.PacketNumber(length) > protocol.MaxTrackedSentPackets {
		return ErrTooManyTrackedSentPackets
	}
	return nil
}

// func (h *sentPacketHandler) MaybeQueueRTOs() {
// 	if time.Now().Before(h.TimeOfFirstRTO()) {
// 		return
// 	}
//
// 	// Always queue the two oldest packets
// 	if h.packetHistory.Front() != nil {
// 		h.queueRTO(h.packetHistory.Front())
// 	}
// 	if h.packetHistory.Front() != nil {
// 		h.queueRTO(h.packetHistory.Front())
// 	}
//
// 	// Reset the RTO timer here, since it's not clear that this packet contained any retransmittable frames
// 	h.lastSentPacketTime = time.Now()
// 	h.consecutiveRTOCount++
// }

func (h *sentPacketHandler) queueRTO(el *PacketElement) {
	packet := &el.Value
	packetsLost := congestion.PacketVector{congestion.PacketInfo{
		Number: packet.PacketNumber,
		Length: packet.Length,
	}}
	h.congestion.OnCongestionEvent(false, h.BytesInFlight(), nil, packetsLost)
	h.congestion.OnRetransmissionTimeout(true)
	utils.Debugf("\tQueueing packet 0x%x for retransmission (RTO)", packet.PacketNumber)
	h.queuePacketForRetransmission(el)
}

// func (h *sentPacketHandler) getRTO() time.Duration {
// 	rto := h.congestion.RetransmissionDelay()
// 	if rto == 0 {
// 		rto = protocol.DefaultRetransmissionTime
// 	}
// 	rto = utils.MaxDuration(rto, protocol.MinRetransmissionTime)
// 	// Exponential backoff
// 	rto *= 1 << h.consecutiveRTOCount
// 	return utils.MinDuration(rto, protocol.MaxRetransmissionTime)
// }
//
// func (h *sentPacketHandler) TimeOfFirstRTO() time.Time {
// 	if h.lastSentPacketTime.IsZero() {
// 		return time.Time{}
// 	}
// 	return h.lastSentPacketTime.Add(h.getRTO())
// }

// func (h *sentPacketHandler) maybeRetransmitLostPackets(lostPackets []*Packet) {
// 	for _, p := range lostPackets {
// 		h.queuePacketForRetransmission(p)
// 	}
// }

func (h *sentPacketHandler) setLossDetectionAlarm() {
	var retransmittablePacketsOutstanding bool
	// TODO: optimize this
	for el := h.packetHistory.Front(); el != nil; el = el.Next() {
		if el.Value.IsRetransmittable() {
			retransmittablePacketsOutstanding = true
			break
		}
	}

	var alarmDuration time.Duration
	if !retransmittablePacketsOutstanding {
		if !h.alarm.Stop() {
			<-h.alarm.C
		}
		return
	}
	// TODO: handle handshake packets separately
	// TODO: implement TLP
	if h.lastSentPacketNumber == h.largestAcked() {
		alarmDuration = h.rttStats.SmoothedRTT() / 4
	} else {
		if h.rtoCount == 0 {
			alarmDuration = utils.MaxDuration(200*time.Millisecond, h.congestion.RetransmissionDelay())
		} else {
			alarmDuration = 2 * h.alarm.GetDelay()
		}
		h.rtoCount++
	}

	utils.Debugf("bla2")
	if !h.alarm.Stop() {
		<-h.alarm.C
	}
	h.alarm.Reset(alarmDuration)
}

func (h *sentPacketHandler) detectLostPackets() []*PacketElement {
	var lost []*PacketElement
	for el := h.packetHistory.Front(); el != nil && el.Value.PacketNumber < h.largestAcked(); el = el.Next() {
		p := el.Value
		if p.SendTime.Before(h.largestAckedPacket.SendTime.Add(-h.rttStats.SmoothedRTT() / 8)) {
			lost = append(lost, el)
		} else if p.PacketNumber < h.largestAcked()-protocol.ReorderingThreshold {
			lost = append(lost, el)
		}
	}
	return lost
}

func (h *sentPacketHandler) runLossDetection() {
	go func() {
		for {
			<-h.alarm.C
			utils.Debugf("Loss detection alarm firing")
			lostPackets := h.detectLostPackets()
			utils.Debugf("lost packets: %#v", lostPackets)
			for _, pEl := range lostPackets {
				h.queuePacketForRetransmission(pEl)
			}
			utils.Debugf("setting loss detection alarm")
			h.setLossDetectionAlarm()
			utils.Debugf("done")
		}
	}()
}

func (h *sentPacketHandler) garbageCollectSkippedPackets() {
	lioa := h.largestInOrderAcked()
	deleteIndex := 0
	for i, p := range h.skippedPackets {
		if p <= lioa {
			deleteIndex = i + 1
		}
	}
	h.skippedPackets = h.skippedPackets[deleteIndex:]
}
