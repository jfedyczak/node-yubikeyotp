crypto = require 'crypto'

mh =
	'c': '0', 'b': '1', 'd': '2', 'e': '3', 'f': '4', 'g': '5', 'h': '6', 'i': '7'
	'j': '8', 'k': '9', 'l': 'a', 'n': 'b', 'r': 'c', 't': 'd', 'u': 'e', 'v': 'f'

crc16 = (buf) ->
	m_crc = 0xffff
	for x in buf
		m_crc ^= x
		for i in [0..7]
			j = m_crc & 1
			m_crc >>= 1
			m_crc ^= 0x8408 if j
	return m_crc

modhexDecode = (s) ->
	w = ''
	w += mh[c] for c in s
	return w

# decode yubikey otp using key as AES key
#   otp - modhex encoded Yubikey OTP
#   key - hex encoded AES key
#
# returns
#   false - if OTP malformed or CRC16 mismatch
#	object - OTP decoded object
parseOTP = (otp, key) ->
	otp = /^([cbdefghiujklnrtuv]{2,32})([cbdefghiujklnrtuv]{32})$/.exec otp

	# malformed OTP
	return false unless otp 

	key = new Buffer key, 'hex'
	
	pub_id = modhexDecode otp[1]
	msg = modhexDecode otp[2]
	msg = new Buffer msg, 'hex'

	decipher = crypto.createDecipheriv 'aes-128-ecb', key, ''
	decipher.setAutoPadding false
	
	data = Buffer.concat [decipher.update(msg), decipher.final()]

	# wrong CRC16 checksum
	return false unless (crc16 data) is 0xf0b8

	result =
		pubUid: pub_id
		uid: data[0..5].toString 'hex'
		useCtr: data[6] + (data[7] << 8)
		tstp: data[8] + (data[9] << 8) + (data[10] << 16)
		sessionCtr: data[11]
		rnd: data[12] + (data[13] << 8)
		crc: data[14] + (data[15] << 8)

	return result

module.exports =
	parseOTP: parseOTP
