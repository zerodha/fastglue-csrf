package gluecsrf

// Config represents the configs for csrf
type Config struct {
	// securecookie key
	AuthKey []byte
	// cookie name
	Name string
	// cookie Max-Age, defaults to 12hrs
	MaxAge int
	// cookie Same-site
	SameSite int
	// cookie path
	Path string
	// cookie domain
	Domain string
}
