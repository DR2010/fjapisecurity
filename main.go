// restauranteapi/restauranteapi.go
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"younitsecurity/helper"

	"github.com/go-redis/redis"
	_ "github.com/go-sql-driver/mysql"
)

var mongodbvar helper.DatabaseX
var redisclient *redis.Client

var db *sql.DB
var err error
var sysid string

// Looks after the main routing
func main() {

	fmt.Println(">>> Web Server: younitsecurity.exe starting...")

	variable := helper.Readfileintostruct()
	RedisAddressPort := variable.RedisAddressPort

	redisclient = redis.NewClient(&redis.Options{
		Addr:     RedisAddressPort,
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	pong, errx := redisclient.Ping().Result()
	fmt.Println(pong, errx)

	if errx != nil {
		log.Fatal("Please update redis configuration or talk to the developer. ABORTING NOW !!!!!!")
	}

	fmt.Println(">>> Web Server: securityapi.exe running.")
	fmt.Println("Loading reference data in cache - Redis")

	sysid = helper.GetSYSID()

	fmt.Println("sysid: " + sysid)

	loadreferencedatainredis()

	SecurityMicroservicePort := helper.Getvaluefromcache("SecurityMicroservicePort")
	SecurityMicroserviceURL := helper.Getvaluefromcache("SecurityMicroserviceURL")
	MongoDBLocation := helper.Getvaluefromcache("API.MongoDB.Location")
	MongoDBDatabase := helper.Getvaluefromcache("API.MongoDB.Database")

	mongodbvar.Location = MongoDBLocation
	mongodbvar.Database = MongoDBDatabase

	if mongodbvar.Location == "" {
		log.Fatal("mongodbvar.Location is EMPTY ")
	}

	router := XNewRouter()

	// handle using the router mux
	//
	http.Handle("/", router) // setting router rule

	fmt.Println("Running... Listening to URL " + SecurityMicroserviceURL)
	fmt.Println("Running... Listening to " + SecurityMicroservicePort)
	fmt.Println("MongoDB location: " + MongoDBLocation)
	fmt.Println("MongoDB database: " + MongoDBDatabase)
	fmt.Println(">>> http.ListenAndServe UP and Running.")

	err := http.ListenAndServe(":"+SecurityMicroservicePort, nil) // setting listening port
	if err != nil {
		//using the mux router
		log.Fatal("ListenAndServe: ", err)
	}
}

//#region Caching

// This is reading from ini file
func loadreferencedatainredis() {

	variable := helper.Readfileintostruct()

	fmt.Println("loadreferencedatainredis - sysid: " + sysid)

	err = redisclient.Set(sysid+"SecurityMicroservicePort", variable.SecurityMicroservicePort, 0).Err()
	if err != nil {
		fmt.Println("loadreferencedatainredis >> " + err.Error())
		log.Println(err)
	}
	err = redisclient.Set(sysid+"SecurityMicroserviceURL", variable.SecurityMicroserviceURL, 0).Err()
	err = redisclient.Set(sysid+"API.MongoDB.Location", variable.APIMongoDBLocation, 0).Err()
	err = redisclient.Set(sysid+"API.MongoDB.Database", variable.APIMongoDBDatabase, 0).Err()
	err = redisclient.Set(sysid+"Web.Debug", variable.WEBDebug, 0).Err()
	err = redisclient.Set(sysid+"CollectionSecurity", variable.CollectionSecurity, 0).Err()

	fmt.Println("variable.APIMongoDBLocation >> " + variable.APIMongoDBLocation)
	fmt.Println("variable.APIMongoDBDatabase >> " + variable.APIMongoDBDatabase)

}

type rediscachevalues struct {
	MongoDBLocation string
	MongoDBDatabase string
	APIServerPort   string
	APIServerIP     string
	WebDebug        string
}

//#endregion Caching

// Cache represents the cache data
type Cache struct {
	Key   string // cache key
	Value string // value in cache
}

func getcachedvalues(httpwriter http.ResponseWriter, req *http.Request) {

	var rv = new(rediscachevalues)

	rv.MongoDBLocation = helper.Getvaluefromcache("API.MongoDB.Location")
	rv.MongoDBDatabase = helper.Getvaluefromcache("API.MongoDB.Database")
	rv.APIServerPort = helper.Getvaluefromcache("API.APIServer.Port")
	rv.APIServerIP = helper.Getvaluefromcache("API.APIServer.IPAddress")
	rv.WebDebug = helper.Getvaluefromcache("Web.Debug")

	keys := make([]Cache, 5)
	keys[0].Key = "API.MongoDB.Location"
	keys[0].Value = rv.MongoDBLocation

	keys[1].Key = "API.MongoDB.Database"
	keys[1].Value = rv.MongoDBDatabase

	keys[2].Key = "API.APIServer.Port"
	keys[2].Value = rv.APIServerPort

	keys[3].Key = "API.APIServer.IPAddress"
	keys[3].Value = rv.APIServerIP

	keys[4].Key = "Web.Debug"
	keys[4].Value = rv.WebDebug

	json.NewEncoder(httpwriter).Encode(&keys)
}
