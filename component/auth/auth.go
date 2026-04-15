package auth

type Authenticator interface {
	Verify(user string, pass string) bool
	Users() []string
}

type AuthStore interface {
	Authenticator() Authenticator
	SetAuthenticator(Authenticator)
}

type AuthUser struct {
	User string
	Pass string
}

type InMemoryAuthenticator struct {
	storage   map[string]string
	usernames []string
}

func (au *InMemoryAuthenticator) Verify(user string, pass string) bool {
	realPass, ok := au.storage[user]
	return ok && realPass == pass
}

func (au *InMemoryAuthenticator) Users() []string { return au.usernames }

// LookupPass returns the password for a given user and whether the user exists.
func (au *InMemoryAuthenticator) LookupPass(user string) (pass string, ok bool) {
	pass, ok = au.storage[user]
	return
}

func NewAuthenticator(users []AuthUser) Authenticator {
	if len(users) == 0 {
		return nil
	}
	au := &InMemoryAuthenticator{
		storage:   make(map[string]string),
		usernames: make([]string, 0, len(users)),
	}
	for _, user := range users {
		au.storage[user.User] = user.Pass
		au.usernames = append(au.usernames, user.User)
	}
	return au
}

var AlwaysValid Authenticator = alwaysValid{}

type alwaysValid struct{}

func (alwaysValid) Verify(string, string) bool { return true }

func (alwaysValid) Users() []string { return nil }
