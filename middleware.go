package go_gin_rbac_middleware

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"regexp"
	"strconv"
	"strings"
	RedisPool "github.com/ynsluhan/go-redis-pool"
	jwt "github.com/ynsluhan/gin-jwt-middleware"
	"github.com/ynsluhan/go-r"
	config "github.com/ynsluhan/go-config"
)

var ctx = context.Background()

//rdb
var rdbSm *redis.Client

// RBAC中间件
func RBACMiddle() gin.HandlerFunc {
	// init 获取rdb
	rdbSm = RedisPool.GetSentinelMaster()
	return func(c *gin.Context) {
		// 获取用户对象
		claims := c.MustGet("claims").(*jwt.CustomClaims)
		// 进行权限判断
		GetPermissions(claims, c)
		//
		c.Next()
	}
}

// 中间件-从redis中获取权限进行判断
func GetPermissions(claims *jwt.CustomClaims, c *gin.Context) {
	// 获取redis中用户权限字符串
	permissionString, err := rdbSm.Get(ctx, config.GetConf().Redis.AdminPrefix+"permission_"+strconv.Itoa(claims.ID)).Result()
	// 判断err
	if err != nil {
		c.Abort()
		// 返回
		R.R(c, 0, err.Error(), nil)
	}
	// string 转 list
	var permissions = strings.Split(permissionString, ",")
	// 创建判断值
	var ex = false
	// 进行权限遍历
	for _, permission := range permissions {
		// 判断管理员
		if permission == ".*" {
			ex = true
			break
		}
		// 进行普通权限匹配
		matchString, _ := regexp.MatchString(permission, c.Request.RequestURI)
		// 匹配成功，将判断值进行赋值
		if matchString == true {
			ex = true
		}
	}
	// 如果为false说明没有匹配成功，反之
	if ex == false {
		// 中断
		c.Abort()
		// 返回
		R.R(c, 403, "permission denied", nil)
	}
}
