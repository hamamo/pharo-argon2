"
Read the paper at https://password-hashing.net/argon2-specs.pdf for an understanding of the different parameters to this password hashing algorithm. The default values are probably ok for non-critical applications.

Notes:
- always initialize the salt before creating a password hash
- the default parameters are just suggestions and are suitable for testing, tune them according to your requirements
- only keep cleartext passwords in memory for the shortest possible time, and erase their contents after use. This is hard to do when garbage collection might be run at any moment, but you should at lease do what you can

Usage:
	""generating""
	hashedPassword := Argon2 new randomizeSalt: 16; hashPassword: 'password'.
	""verifying""
	Argon2 new verifyPassword: 'password' hash: hashedPassword
"
Class {
	#name : #Argon2,
	#superclass : #Object,
	#instVars : [
		'version',
		'type',
		't_cost',
		'm_cost',
		'parallelism',
		'saltBytes',
		'saltLen',
		'hashBytes',
		'hashLen',
		'encodedBytes',
		'encodedLen'
	],
	#classVars : [
		'ARGON2_VERIFY_MISMATCH',
		'Argon2_d',
		'Argon2_i',
		'Argon2_id',
		'Argon2d',
		'Argon2i',
		'Argon2id'
	],
	#category : #'PasswordHashing-Argon2'
}

{ #category : #'class initialization' }
Argon2 class >> initialize [
	"we don't have to know all error codes, anything other than password mismatch is being handled by argon2_error_message()"
	ARGON2_VERIFY_MISMATCH := -35.
	Argon2_d := 0.
	Argon2_i := 1.
	Argon2_id := 2
]

{ #category : #'private-ffi' }
Argon2 >> argon2_encodedlen [
	^self ffiCall: #(int argon2_encodedlen(
							const uint32 t_cost, const uint32 m_cost, const uint32 parallelism,
							const size_t saltLen,
							const size_t hashLen,
							int type))
]

{ #category : #'private-ffi' }
Argon2 >> argon2_error_message: error_code [
	^self ffiCall: #(const char *argon2_error_message(int error_code))
]

{ #category : #'private-ffi' }
Argon2 >> argon2_hash: passwordBytes len: passwordLen [
	^self ffiCall: #(int argon2_hash(
							const uint32 t_cost, const uint32 m_cost, const uint32 parallelism,
							const void *passwordBytes, const size_t passwordLen,
							const void *saltBytes, const size_t saltLen,
							void *hashBytes, const size_t hashLen,
							char *encodedBytes, const size_t encodedLen,
							int type, const uint32 version))
]

{ #category : #'private-ffi' }
Argon2 >> argon2_verify: passwordBytes len: passwordLen [
	^self ffiCall: #(int argon2_verify(
							const char *encodedBytes,
							const void *passwordBytes, const size_t passwordLen,
							int type))
]

{ #category : #acccessing }
Argon2 >> ffiLibraryName [
	^Argon2Library
]

{ #category : #acccessing }
Argon2 >> hashBytes: aByteArray [
	hashBytes := aByteArray.
	hashLen := hashBytes size
]

{ #category : #acccessing }
Argon2 >> hashLen: anInteger [
	self hashBytes: (ByteArray new: anInteger)
]

{ #category : #'password hashing' }
Argon2 >> hashPassword: aString [
	| bytes result |
	bytes := aString utf8Encoded.
	encodedLen := self argon2_encodedlen.
	encodedBytes := ByteArray new: encodedLen.
	result := self argon2_hash: bytes len: bytes size.
	bytes atAllPut: 0.
	result = 0 ifFalse: [self error: 'Argon2 error: ', (self argon2_error_message: result)].
	^encodedBytes readString
]

{ #category : #initialization }
Argon2 >> initialize [
	type := Argon2_i.	"recommended for password hashing, avoids side channel effects at a cost of somewhat decreased resistance to brute force attacks which can be mitigated by selecting other parameters. See the Argon2 paper at https://password-hashing.net/argon2-specs.pdf"
	version := 16r13.
	t_cost := 2.
	m_cost := 65536.
	parallelism := 1.
	self saltBytes: (ByteArray new: 16).
	self hashBytes: (ByteArray new: 32).
	
]

{ #category : #acccessing }
Argon2 >> m_cost: anInteger [
	m_cost := anInteger
]

{ #category : #acccessing }
Argon2 >> parallelism: anInteger [
	parallelism := anInteger
]

{ #category : #initialization }
Argon2 >> randomizeSalt: anInteger [
	"generate a random salt of given length"
	| rnd |
	rnd := Random new.
	self saltBytes: ((1 to: anInteger) collect: [ :i | (rnd nextInt: 256)-1 ]) asByteArray
	
	
	
]

{ #category : #acccessing }
Argon2 >> saltBytes: aByteArray [
	saltBytes := aByteArray.
	saltLen := saltBytes size
]

{ #category : #acccessing }
Argon2 >> t_cost: anInteger [
	t_cost := anInteger
]

{ #category : #acccessing }
Argon2 >> type: anInteger [
	self assert: [ anInteger isInteger and: [ anInteger between: 0 and: 3 ] ] description: 'Argon 2 type must be between 0 and 2'.
	type := anInteger
]

{ #category : #'password hashing' }
Argon2 >> verifyPassword: aString hash: anEncodedHash [
	| bytes result |
	bytes := aString utf8Encoded.
	encodedBytes := anEncodedHash.
	result := self argon2_verify: bytes len: bytes size.
	bytes atAllPut: 0.
	result = ARGON2_VERIFY_MISMATCH ifTrue: [ ^false ].
	result = 0 ifFalse: [self error: 'Argon2 error: ', (self argon2_error_message: result)].
	^true
]
