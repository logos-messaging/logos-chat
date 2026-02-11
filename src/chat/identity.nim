
import crypto/ecdh
import results
import strformat
import utils

export PublicKey, PrivateKey, loadPrivateKeyFromBytes, loadPublicKeyFromBytes 


type
  Identity* = object
    name*: string
    privateKey*: PrivateKey   # TODO: protect key exposure


#################################################
# Constructors
#################################################

proc createIdentity*(name: string): Identity =
  let privKey = createRandomKey().get()
  result = Identity(name: name, privateKey: privKey)


#################################################
# Parameter Access
#################################################

proc getPubkey*(self: Identity): PublicKey =
  result = self.privateKey.getPublicKey()

proc getAddr*(self: Identity): string =
  result = get_addr(self.getPubKey())


proc getName*(self: Identity): string =
  result = self.name
