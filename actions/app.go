package actions

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"oidctest/locales"
	"oidctest/public"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gobuffalo/buffalo"
	"github.com/gobuffalo/envy"
	forcessl "github.com/gobuffalo/mw-forcessl"
	i18n "github.com/gobuffalo/mw-i18n/v2"
	paramlogger "github.com/gobuffalo/mw-paramlogger"
	"github.com/gorilla/sessions"
	"github.com/unrolled/secure"
)

// ENV is used to help switch settings based on where the
// application is being run. Default is "development".
var ENV = envy.Get("GO_ENV", "development")

var (
	app *buffalo.App
	T   *i18n.Translator
)

// App is where all routes and middleware for buffalo
// should be defined. This is the nerve center of your
// application.
//
// Routing, middleware, groups, etc... are declared TOP -> DOWN.
// This means if you add a middleware to `app` *after* declaring a
// group, that group will NOT have that new middleware. The same
// is true of resource declarations as well.
//
// It also means that routes are checked in the order they are declared.
// `ServeFiles` is a CATCH-ALL route, so it should always be
// placed last in the route declarations, as it will prevent routes
// declared after it to never be called.
func App() *buffalo.App {
	if app == nil {
		app = buffalo.New(buffalo.Options{
			Env:          ENV,
			SessionName:  "_oidctest_session",
			SessionStore: sessions.NewCookieStore([]byte("some session secret")),
		})

		// Automatically redirect to SSL
		// app.Use(forceSSL())

		// Log request parameters (filters apply).
		app.Use(paramlogger.ParameterLogger)

		// Protect against CSRF attacks. https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)
		// Remove to disable this.
		// app.Use(csrf.New)

		// Setup and use translations:
		app.Use(translations())

		app.GET("/", RootHandler)

		app.GET("/login", LoginHandler)
		app.POST("/login", LoginHandler)

		alluser := app.Group("/authed")
		alluser.Use(islogin)
		alluser.GET("/logout", LogoutHandler)
		alluser.GET("/home", HomeHandler)

		u := alluser.Group("/dash")
		u.Use(requestIAM)
		u.GET("/admin", AdminDashHandler)
		u.GET("/user", UserDashHandler)

		u2 := alluser.Group("/dash2")
		u2.Use(requestIAM)
		u2.GET("/price", PriceDashHandler)

		protected := app.Group("/protected")
		protected.Use(islogin)
		protected.Use(requestIAM)
		protected.GET("/premium", PremiumHandler)

		app.ServeFiles("/", http.FS(public.FS())) // serve files from the public directory
	}

	return app
}

var KC_uri = os.Getenv("KC_uri")
var KC_clientID = os.Getenv("KC_clientID")
var KC_clientSecret = os.Getenv("KC_clientSecret")
var KC_realm = os.Getenv("KC_realm")
var KC_client = gocloak.NewClient(KC_uri)

// translations will load locale files, set up the translator `actions.T`,
// and will return a middleware to use to load the correct locale for each
// request.
// for more information: https://gobuffalo.io/en/docs/localization
func translations() buffalo.MiddlewareFunc {
	var err error
	if T, err = i18n.New(locales.FS(), "en-US"); err != nil {
		app.Stop(err)
	}
	return T.Middleware()
}

// forceSSL will return a middleware that will redirect an incoming request
// if it is not HTTPS. "http://example.com" => "https://example.com".
// This middleware does **not** enable SSL. for your application. To do that
// we recommend using a proxy: https://gobuffalo.io/en/docs/proxy
// for more information: https://github.com/unrolled/secure/
func forceSSL() buffalo.MiddlewareFunc {
	return forcessl.Middleware(secure.Options{
		SSLRedirect:     ENV == "production",
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
	})
}

func islogin(next buffalo.Handler) buffalo.Handler {
	return func(c buffalo.Context) error {
		token := fmt.Sprintf("%s", c.Session().Get("token"))
		_, jwt, decodeerr := KC_client.DecodeAccessToken(c, token, KC_realm)

		if decodeerr != nil || jwt.Valid() != nil {
			fmt.Println("$$$$$$$$$$$$$$$$$$$$$$$$ Token err $$$$$$$$$$$$$$$$$$$$$$$$")
			return c.Redirect(302, "/")
		}
		err := next(c)
		return err
	}
}

func requestIAM(next buffalo.Handler) buffalo.Handler {
	return func(c buffalo.Context) error {
		currentURL := c.Request().URL.String()
		currentMethod := c.Request().Method
		bearer := "Bearer " + fmt.Sprintf("%s", c.Session().Get("token"))

		req, err := http.NewRequest(currentMethod, os.Getenv("IAM_Filter_endpoint")+currentURL, nil)
		if err != nil {
			panic(err)
		}
		req.Header.Add("Authorization", bearer)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error on response.\n[ERROR] -", err)
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println("Error while reading the response bytes:", err)
		}

		fmt.Println(string([]byte(body)))
		if strings.Contains(string([]byte(body)), "Hello") {
			fmt.Println("Good to go")
			err = next(c)
		} else {
			fmt.Println("Access denide")
			return c.Redirect(302, "/")
		}

		return err
	}
}
