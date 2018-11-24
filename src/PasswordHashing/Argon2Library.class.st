Class {
	#name : #Argon2Library,
	#superclass : #FFILibrary,
	#category : #'PasswordHashing-Argon2'
}

{ #category : #'accessing platform' }
Argon2Library >> unixModuleName [
	^'libargon2.so'
]
