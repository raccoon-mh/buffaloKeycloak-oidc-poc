package actions

import (
	"log"
	"net/http"

	"github.com/gobuffalo/buffalo"
)

type User struct {
	ID       string `json:"ID"`
	Password string `json:"Password"`
}

func RootHandler(c buffalo.Context) error {
	return c.Render(http.StatusOK, r.HTML("defaulthome/index.html"))
}

func LoginHandler(c buffalo.Context) error {
	if c.Request().Method == "GET" {
		return c.Render(http.StatusOK, r.HTML("login/login.html"))
	} else if c.Request().Method == "POST" {
		u := &User{}
		if err := c.Bind(u); err != nil {
			return c.Render(http.StatusOK, r.JSON(map[string]interface{}{
				"err": err.Error(),
			}))
		}
		log.Printf("LoginHandler Posted -- ID : %s PW : %s", u.ID, u.Password)

		token, err := KC_client.Login(c, KC_clientID, KC_clientSecret, KC_realm, u.ID, u.Password)
		if err != nil {
			return c.Render(http.StatusOK, r.JSON(map[string]interface{}{
				"err": err.Error(),
			}))
		}
		log.Printf("LoginHandler success -- User ID : %s Token : %s", u.ID, token.AccessToken)

		c.Session().Set("token", token.AccessToken)

		return c.Redirect(302, "/authed/home")
	}

	return c.Render(http.StatusOK, r.HTML("login/login.html"))

}

func LogoutHandler(c buffalo.Context) error {
	c.Session().Clear()
	return c.Redirect(302, "/")
}

func HomeHandler(c buffalo.Context) error {
	// fmt.Println(c.Session().Get("token"))
	return c.Render(http.StatusOK, r.HTML("Home/index.html"))
}

func AdminDashHandler(c buffalo.Context) error {
	return c.Render(http.StatusOK, r.HTML("Dash/adminDash.html"))
}

func UserDashHandler(c buffalo.Context) error {
	return c.Render(http.StatusOK, r.HTML("Dash/userDash.html"))
}

func PriceDashHandler(c buffalo.Context) error {
	return c.Render(http.StatusOK, r.HTML("Dash/priceDash.html"))
}
