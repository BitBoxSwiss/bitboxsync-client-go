// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import "time"

func (e *Engine) emitItem(item ItemState, eventType EventType) {
	e.emit(Event{
		Type:        eventType,
		NamespaceID: item.NamespaceID,
		Collection:  item.Collection,
		Key:         item.Key,
		ItemID:      item.ItemID,
	})
}

// emit delivers an ordered event to the buffered event channel. If the caller
// does not read from Events, the engine may block here.
func (e *Engine) emit(event Event) {
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	e.eventMu.RLock()
	defer e.eventMu.RUnlock()
	if e.eventsClosed {
		return
	}
	if isSyncActivityEvent(event.Type) {
		e.activitySeq.Add(1)
	}
	e.events <- event
}

func isSyncActivityEvent(eventType EventType) bool {
	switch eventType {
	case EventNamespaceChanged,
		EventItemChanged,
		EventItemDownloaded,
		EventItemUploaded,
		EventConflictDetected,
		EventUnknownRemoteItem:
		return true
	default:
		return false
	}
}
