package lib

import (
	"context"
	"log"
	"os"
	"sync"

	"github.com/go-redis/redis/v8"
)

var client *redis.Client
var once sync.Once

// Redis client is already multiplexed and long lived. It is threadsafe so it
// should be able to be accessed by multiple registration threads concurrently
// with no issues. PoolSize is tunable in case this ends up being an issue.
func getRedisClient(pwd string) *redis.Client {
	once.Do(func() {
		initRedisClient(pwd)
	})
	return client
}

func initRedisClient(pwd string) {
	client = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: pwd,
		DB:       0,
		PoolSize: 100,
	})

	ctx := context.Background()
	// Ping to test redis connection
	_, err := client.Ping(ctx).Result()
	if err != nil {
		logger := log.New(os.Stderr, "[REDIS] ", log.Ldate|log.Lmicroseconds)
		logger.Printf("redis connection ping failed.")
	}
}
