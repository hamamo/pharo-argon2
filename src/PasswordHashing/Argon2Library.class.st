Class {
	#name : #Argon2Library,
	#superclass : #FFILibrary,
	#category : #'PasswordHashing-Argon2'
}

{ #category : #'accessing platform' }
Argon2Library >> unix32ModuleName [
	^'/usr/lib/i386-linux-gnu/libargon2.so.0'
]

{ #category : #'accessing platform' }
Argon2Library >> unixModuleName [
	^'libargon2.so'
]
