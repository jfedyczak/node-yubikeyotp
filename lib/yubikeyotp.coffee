crypto = require 'crypto'
request = require 'request'
querystring = require 'querystring'

mh =
	'c': '0', 'b': '1', 'd': '2', 'e': '3', 'f': '4', 'g': '5', 'h': '6', 'i': '7'
	'j': '8', 'k': '9', 'l': 'a', 'n': 'b', 'r': 'c', 't': 'd', 'u': 'e', 'v': 'f'

# Calculate CRC16 from buffer
crc16 = (buf) ->
	m_crc = 0xffff
	for x in buf
		m_crc ^= x
		for i in [0..7]
			j = m_crc & 1
			m_crc >>= 1
			m_crc ^= 0x8408 if j
	return m_crc

# Decode hex string from modhex string
modhexDecode = (s) ->
	w = ''
	w += mh[c] for c in s
	return w

# Compare two strings
cmp = (a, b) -> if a < b then -1 else if a > b then 1 else 0

# Decode yubikey otp using key as AES key
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

# online verification with Yubico Web API v2.0
verifyOTP = (options, callback) ->

	# set defaults
	options.apiUrl ?= "https://api.yubico.com/wsapi/2.0/verify"
	options.requestParams ?= {}
	options.timestamp ?= false
	options.sl ?= false
	options.timeout ?= false

	# this will not block
	options.nonce ?= crypto.pseudoRandomBytes 24
		.toString 'base64'
		.replace /[^0-9a-zA-Z]/g, ''

	params =
		id: options.id
		nonce: options.nonce
		otp: options.otp

	params.timestamp = 1 if options.timestamp
	params.sl = options.sl unless options.sl is false
	params.timeout = options.timeout unless options.timeout is false

	# sign the message using HMAC-SHA1 if key given
	if 'key' of options

		# alphabetical order needed for signing
		keys = (k for k of params).sort cmp
		qs = ("#{k}=#{params[k]}" for k in keys).join '&'

		# calculating HMAC-SHA1 using base64-encoded key
		hmac = crypto.createHmac 'sha1', new Buffer options.key, 'base64'
		hmac.update qs
		h = hmac.digest 'base64'

		h = querystring.encode h
		
		# append base64-encoded HMAC to query string
		qs += "&h=#{h}"
	else
		# ordering irrelevant in this case
		qs = ("#{k}=#{v}" for k, v of params).join '&'

	requestParams = options.requestParams
	requestParams.uri = "#{options.apiUrl}?#{qs}"

	request requestParams, (e, r, body) ->
		return callback e if e
		return callback 'No HTTP status code' unless r and r.statusCode?
		return callback "HTTP status code: #{r.statusCode}" unless r.statusCode is 200

		result = {}
		for line in body.trim().split "\r\n"
			[k, v] = line.split "="
			result[k] = v

		# response has to have OTP
		return callback 'No OTP in result' unless 'otp' of result

		# ... and it has to match the original
		return callback 'OTP mismatch' unless result.otp is options.otp

		# verify signature if requested
		if 'key' of options
			return callback 'No signature in response' unless 'h' of result

			# alphabetical order needed for signing
			keys = (k for k of result)
				.filter (x) -> x isnt 'h'
				.sort cmp
			qs = ("#{k}=#{result[k]}" for k in keys).join '&'

			# calculating HMAC-SHA1 using base64-encoded key
			hmac = crypto.createHmac 'sha1', new Buffer options.key, 'base64'
			hmac.update qs
			h = hmac.digest 'base64'
				.replace /\=/g, ''

			return callback 'Signature mismatch' unless h is result.h

		# response looks legitimate
		callback null, result

module.exports =
	parseOTP: parseOTP
	verifyOTP: verifyOTP
