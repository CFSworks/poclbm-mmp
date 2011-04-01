import platform
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from MMPProtocol import MMPClient
from BitcoinMiner import *

class MMPBitcoinMiner(BitcoinMiner):
	def __init__(self, device, host, user, password, port=8332, *args, **kwargs):
		self.client = MMPClient(self)
		self.clientargs = (host, port, user, password)
		
		self.name = kwargs.get('name','')
		
		self.lastRateUpdate = 0.0
		self.serverMsgBanner = False
		self.workRequested = False
		return BitcoinMiner.__init__(self, device, host, user, password, port, *args, **kwargs)

	def say(self, *args):
		self.serverMsgBanner = False
		BitcoinMiner.say(self, *args)
	
	def hashrate(self, rate):
		if time() > (self.lastRateUpdate + 30.0):
			self.client.setMeta('rate', rate)
			self.lastRateUpdate = time()
		BitcoinMiner.hashrate(self, rate)
		
	def mine(self):
		self.stop = False
		Thread(target=self.miningThread).start()

		self.client.setMeta('device', self.device.name.replace('\x00',''))
		self.client.setMeta('version', 'poclbm v%s by m0mchil' % (VERSION,))
		if self.name:
			self.client.setMeta('name', self.name)
		self.client.setMeta('os', platform.system() + ' ' + platform.version())
		self.client.setMeta('cores', self.device.max_compute_units)
		
		self.client.connect(*self.clientargs)
		LoopingCall(self.checkQueues).start(0.5)
		reactor.run()
	
	def onConnect(self):
		self.sayLine('connected')
	def onDisconnect(self):
		self.sayLine('lost connection')
	
	def onMsg(self, message):
		if not self.serverMsgBanner:
			self.sayLine('server message(s):')
		self.say(message + '\n')
		self.serverMsgBanner = True
	
	def onWork(self, wu):
		self.workRequested = False
		work = {
			'midstate': pack('I'*8, *sha256(STATE, np.array(unpack('I'*64, wu.data[:64] + '\x00'*192), dtype=np.uint32)).tolist()).encode('hex'),
			'data': wu.data.encode('hex') + '00000080' + ('00'*40) + '80020000',
			'target': wu.target.encode('hex'),
			'mask': wu.mask
		}
		with self.lock:
			self.queueWork(work)
	
	def sendResult(self, result):
		for i in xrange(OUTPUT_SIZE):
			if result['output'][i]:
				h = hash(result['state'], result['data'][0], result['data'][1], result['data'][2], result['output'][i])
				if h[7] != 0:
					self.failure('Verification failed, check hardware!')
				else:
					self.diff1Found(bytereverse(h[6]), result['target'][6])
					if belowOrEquals(h[:7], result['target'][:7]):
						if result['work'] is None:
							return
						d = result['work']['data']
						d = ''.join([d[:136], pack('I', long(result['data'][1])).encode('hex'), d[144:152], pack('I', long(result['output'][i])).encode('hex')])
						deferred = self.client.sendResult(d.decode('hex'))
						def callback(accepted):
							self.blockFound(pack('I', long(h[6])).encode('hex'), accepted)
						deferred.addCallback(callback)
	
	def checkQueues(self):
		if self.stop:
			reactor.stop()
			return
		with self.lock:
			if self.update and not self.workRequested:
				self.workRequested = True
				self.client.requestWork()
			if not self.resultQueue.empty():
				self.sendResult(self.resultQueue.get(False))