# radioactive
import hashlib


print """

hash cracker version 1.0

coded by radioactive

[*]-md5
[*]-sha1
[*]-sha224
[*]-sha256
[*]-sha384
[*]-sha512

"""
try:
	hashing = raw_input("Enter Your hash : ")
	type_hash = raw_input("Enter type hash : ")
	file = raw_input("Enter wordlist exmple passlist.txt :")

	wordlist = open(file,"r").readlines()

	for password in wordlist:
		password = password.strip()

		if type_hash == "md5":
			hash_a = hashlib.md5(password).hexdigest()
		elif type_hash == "sha1":
			hash_a = hashlib.sha1(password).hexdigest()

		elif type_hash == "sha224":
			hash_a = hashlib.sha224(password).hexdigest()
		elif type_hash == "sha256":
			hash_a = hashlib.sha256(password).hexdigest()
		elif type_hash == "sha384":
			hash_a = hashlib.sha384(password).hexdigest()
		elif type_hash == "sha512":
			hash_a = hashlib.sha512(password).hexdigest()
		if hashing == hash_a:
			print "[+] hash is cracked > ",password
			break
		else:
			print "[-] try test ",password
except:
	print "[!] plz check input "
