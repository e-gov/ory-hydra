package server

import "sync"

type void struct{}

type StopNotifier struct {
	channels []chan void
	mutex    sync.Mutex
	stopped  bool
}

func NewStopNotifier() *StopNotifier {
	return &StopNotifier{
		stopped: false,
	}
}

func (self *StopNotifier) Notify() {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	if !self.stopped {
		self.stopped = true
		for _, channel := range self.channels {
			close(channel)
		}
	}
}

func (self *StopNotifier) Wait() {
	self.mutex.Lock()

	if self.stopped {
		self.mutex.Unlock()
		return
	}

	channel := make(chan void)
	self.channels = append(self.channels, channel)
	self.mutex.Unlock()

	<-channel
}
