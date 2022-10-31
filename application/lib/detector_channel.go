package lib

import (
	"context"
	golog "log"
	"os"
	"sync"

	"github.com/go-redis/redis/v8"

	"github.com/refraction-networking/conjure/application/log"
)

var client *redis.Client
var once sync.Once

// Redis client is already multiplexed and long lived. It is threadsafe so it
// should be able to be accessed by multiple registration threads concurrently
// with no issues. PoolSize is tunable in case this ends up being an issue.
func getRedisClient() *redis.Client {
	once.Do(initRedisClient)
	return client
}

func initRedisClient() {
	client = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
		PoolSize: 100,
	})

	ctx := context.Background()
	// Ping to test redis connection
	_, err := client.Ping(ctx).Result()
	if err != nil {
		logger := log.New(os.Stderr, "[REDIS] ", golog.Ldate|golog.Lmicroseconds)
		logger.Errorf("redis connection ping failed.")
	}
}
