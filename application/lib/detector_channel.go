package lib

import (
	"log"
	"os"
	"sync"

	"github.com/go-redis/redis"
)

var client *redis.Client
var once sync.Once

func getRedisClient() *redis.Client {
	once.Do(initRedisClient)
	return client
}

func initRedisClient() {
	client = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
		PoolSize: 10,
	})

	// Ping to test redis connection
	_, err := client.Ping().Result()
	if err != nil {
		logger := log.New(os.Stderr, "[REDIS] ", log.Ldate|log.Lmicroseconds)
		logger.Printf("redis connection ping failed.")
	}
}

// func getRedisClient() (*redis.Client, error) {
// 	var client *redis.Client
// 	client = redis.NewClient(&redis.Options{
// 		Addr:     "localhost:6379",
// 		Password: "",
// 		DB:       0,
// 		PoolSize: 10,
// 	})

// 	_, err := client.Ping().Result()
// 	if err != nil {
// 		return client, err
// 	}

// 	return client, err
// }
