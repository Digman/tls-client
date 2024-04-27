package tls_client

import (
	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	"net/url"
)

type CookieJarOption func(config *cookieJarConfig)

type cookieJarConfig struct {
	skipExisting bool
	debug        bool
	logger       Logger
}

func WithSkipExisting() CookieJarOption {
	return func(config *cookieJarConfig) {
		config.skipExisting = true
	}
}

func WithDebugLogger() CookieJarOption {
	return func(config *cookieJarConfig) {
		config.debug = true
	}
}

type CookieJar struct {
	jar    *cookiejar.Jar
	config *cookieJarConfig
}

func NewCookieJar(options ...CookieJarOption) *CookieJar {
	realJar, _ := cookiejar.New(nil)

	config := &cookieJarConfig{}

	for _, opt := range options {
		opt(config)
	}

	config.logger = NewNoopLogger()

	if config.debug {
		config.logger = NewDebugLogger(config.logger)
	}

	c := &CookieJar{
		jar:    realJar,
		config: config,
	}

	return c
}

func (j *CookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if j.jar == nil {
		j.config.logger.Warn("cookiejar is nil")
		return
	}

	var filteredCookies []*http.Cookie

	if j.config.skipExisting {
		existingCookies := j.jar.Cookies(u)

		for _, cookie := range cookies {
			alreadyInJar := false

			for _, existingCookie := range existingCookies {
				alreadyInJar = cookie.Name == existingCookie.Name && cookie.Domain == existingCookie.Domain

				if alreadyInJar {
					break
				}
			}

			if alreadyInJar {
				j.config.logger.Debug("cookie %s is already in jar", cookie.Name)
				continue
			}

			filteredCookies = append(filteredCookies, cookie)
		}
	} else {
		filteredCookies = cookies
	}

	j.jar.SetCookies(u, filteredCookies)
}

func (j *CookieJar) Cookies(u *url.URL) []*http.Cookie {
	if j.jar == nil {
		j.config.logger.Warn("cookiejar is nil")
		return nil
	}
	return j.jar.Cookies(u)
}
