package middleware

import "github.com/gin-gonic/gin"

func newTestEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}
