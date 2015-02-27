beanstalkc.py :
	is a modified version of the official v0.4.0 driver enabling connection to servers with auth ON
	there is a new class AuthConnection, which extends the normal Connection, adding the possibility to add an username and password
	also (to easen the usage of auth servers on actual envs) the connection class transparently reads the creds from a file in a specific path
	
	the client does an initial "read" on "connect" to search for the "AUTH_REQUIRED" tag, if found does the "hand-shake"
bs_user.sh:
	creates the hash to store in the credential repo, is the same for both sides (serve & client)
	!!! it's a dummy script, does no args check !!!
	Es.:
		./bs_user.sh <user> <password> > <file>