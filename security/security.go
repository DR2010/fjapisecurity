// Package security is a security for packages
// -------------------------------------
// .../restauranteapi/security/security.go
// -------------------------------------
package security

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"
	helper "younitsecurity/helper"

	"github.com/go-redis/redis"

	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// Credentials is to be exported
type Credentials struct {
	SystemID         bson.ObjectId `json:"id"        bson:"_id,omitempty"`
	UserID           string        //
	Name             string        //
	Password         string        //
	PasswordValidate string        //
	ApplicationID    string        //
	CentroID         string        //
	MobilePhone      string        //
	Expiry           string        //
	JWT              string        //
	TokenJWT         Token
	KeyJWT           string  //
	ClaimSet         []Claim //
	Status           string  // It is set to Active manually by Daniel 'Active' or Inactive.
	IsAdmin          string  //
	IsAnonymous      string  //
	ResetCode        string  //
}

// Token is the data structure for any token in the database. Note that
// we do not send the TokenHash (a slice of bytes) in any exported JSON.
type Token struct {
	ID        int       `json:"id"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Token     string    `json:"token"`
	TokenHash []byte    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Expiry    time.Time `json:"expiry"`
}

// Claim is
type Claim struct {
	Type  string
	Value string
}

// Useradd is for export
func Useradd(sysid string, redisclient *redis.Client, userInsert Credentials) helper.Resultado {

	database := helper.GetDBParmFromCache("CollectionSecurity")

	session, err := mgo.Dial(database.Location)
	if err != nil {
		panic(err)
	}
	defer session.Close()

	// Optional. Switch the session to a monotonic behavior.
	session.SetMode(mgo.Monotonic, true)

	collection := session.DB(database.Database).C(database.Collection)

	err = collection.Insert(userInsert)

	if err != nil {
		log.Fatal(err)

		var resX helper.Resultado
		resX.ErrorCode = "405 Error creating user"
		resX.ErrorDescription = "Error adding user"
		resX.IsSuccessful = "N"
		return resX

	}

	var res helper.Resultado
	res.ErrorCode = "200 OK"
	res.ErrorDescription = "User added"
	res.IsSuccessful = "Y"

	return res
}

// Find is to find stuff
func Find(userinfo helper.UserInfo) (Credentials, string) {

	database := helper.GetDBParmFromCache("CollectionSecurity")

	log.Println("Looking for " + userinfo.Userid)
	log.Println("...on DB: " + database.Database)
	log.Println("database.Location: " + database.Location)

	dishnull := Credentials{}

	var hostName = "192.168.1.200" // database.Location
	var port = "27017"
	var dbName = "" // database.Database

	uri := fmt.Sprintf("mongodb://%s:%s/%s", hostName, port, dbName)

	session, err := mgo.Dial(uri)
	// session, err := mgo.Dial(database.Location + ":27017")
	if err != nil {
		log.Println("err.Error: " + err.Error())
		panic(err)
	}
	defer session.Close()

	// Optional. Switch the session to a monotonic behavior.
	session.SetMode(mgo.Monotonic, true)

	c := session.DB(database.Database).C(database.Collection)

	result := []Credentials{}
	err1 := c.Find(bson.M{"userid": userinfo.Userid}).All(&result)
	if err1 != nil {
		// log.Fatal(err1)
		log.Println(err1)
	}

	var numrecsel = len(result)

	if numrecsel <= 0 {
		log.Println("404 Not found -> " + userinfo.Userid)
		return dishnull, "404 Not found"
	}

	log.Println("...ApplicationID: " + result[0].ApplicationID)

	return result[0], "200 OK"
}

// UsersGetAll is to retrieve all users
func UsersGetAll() ([]Credentials, string) {

	database := helper.GetDBParmFromCache("CollectionSecurity")

	session, err := mgo.Dial(database.Location)
	if err != nil {
		panic(err)
	}
	defer session.Close()

	// Optional. Switch the session to a monotonic behavior.
	session.SetMode(mgo.Monotonic, true)

	c := session.DB(database.Database).C(database.Collection)

	var results []Credentials

	err1 := c.Find(nil).All(&results)
	if err1 != nil {
		log.Fatal(err1)
	}

	return results, "200 OK"

}

// Userupdate is
func Userupdate(userUpdate Credentials) helper.Resultado {

	database := helper.GetDBParmFromCache("CollectionSecurity")

	session, err := mgo.Dial(database.Location)
	if err != nil {
		panic(err)
	}
	defer session.Close()

	// Optional. Switch the session to a monotonic behavior.
	session.SetMode(mgo.Monotonic, true)

	collection := session.DB(database.Database).C(database.Collection)

	userUpdate.UserID = strings.ToUpper(userUpdate.UserID)

	err = collection.Update(bson.M{"userid": userUpdate.UserID}, userUpdate)

	var res helper.Resultado
	res.ErrorCode = "0001"
	res.ErrorDescription = "Something Happened"
	res.IsSuccessful = "Y"

	if err != nil {
		log.Println(err)
		res.ErrorCode = "0201"
		res.ErrorDescription = "Error"
		res.IsSuccessful = "N"
	}

	return res
}

// ValidateUserCredentials is to find stuff
func ValidateUserCredentials(userinfo helper.UserInfo) (string, string) {

	// look for user
	var us, _ = Find(userinfo)

	var passwordhashed = Hashstring(userinfo.Password)

	if passwordhashed != us.Password {
		return "Error", "404 Error"
	}

	var jwt = getjwtfortoday(userinfo.Userid)
	return jwt, "200 OK"
}

// ValidateUserCredentialsV2 is to find stuff
func ValidateUserCredentialsV2(userinfo helper.UserInfo) (Credentials, string) {

	var usercredentials Credentials
	usercredentials.UserID = userinfo.Userid
	usercredentials.ApplicationID = "None"
	usercredentials.JWT = "Error"
	usercredentials.Status = "Error"

	// look for user
	var userdatabase, _ = Find(userinfo)

	var passwordhashed = Hashstring(userinfo.Password)

	if passwordhashed != userdatabase.Password {
		usercredentials.Status = "404 Error invalid password"
		return usercredentials, "404 Error"
	}

	// Get the JWT
	// var jwt = getjwtfortoday(userinfo.Userid)
	var jwt, err = GenerateToken(userinfo.Userid, 2*time.Hour)

	// Assign the JWT to the return JSON object Credentials

	if err != nil {
		usercredentials.UserID = userinfo.Userid
		usercredentials.ApplicationID = "None"
		usercredentials.JWT = "Error"
		usercredentials.Status = "Error"
		return usercredentials, err.Error()
	}

	userdatabase.JWT = jwt.Token
	userdatabase.TokenJWT = jwt

	userdatabase.IsAdmin = "No"
	// Check if user is admin
	for x := 0; x < len(userdatabase.ClaimSet); x++ {
		if userdatabase.ClaimSet[x].Type == "USERTYPE" {
			if userdatabase.ClaimSet[x].Value == "ADMIN" {
				// list all if user is admin
				userdatabase.IsAdmin = "Yes"
				break
			}
		}
	}

	return userdatabase, "200 OK"
}

func keyfortheday(day int) string {

	var key = "De tudo, ao meu amor serei atento antes" +
		"E com tal zelo, e sempre, e tanto" +
		"Que mesmo em face do maior encanto" +
		"Dele se encante mais meu pensamento" +
		"Quero vivê-lo em cada vão momento" +
		"E em seu louvor hei de espalhar meu canto" +
		"E rir meu riso e derramar meu pranto" +
		"Ao seu pesar ou seu contentamento" +
		"E assim quando mais tarde me procure" +
		"Quem sabe a morte, angústia de quem vive" +
		"Quem sabe a solidão, fim de quem ama" +
		"Eu possa lhe dizer do amor que tive" +
		"Que não seja imortal, posto que é chama" +
		"Mas que seja infinito enquanto dure"

	stringSlice := strings.Split(key, " ")
	var stringSliceFinal [100]string

	x := 0
	for i := 0; i < len(stringSlice); i++ {
		if len(stringSlice[i]) > 3 {
			stringSliceFinal[x] = stringSlice[i]
			x++
		}
	}

	return stringSliceFinal[day]
}

// getjwtfortoday
// this is just a reference key
// the roles, date and user will be stored at the server
func getjwtfortoday(user string) string {

	// Generate Key
	_, _, day := time.Now().Date()
	s := keyfortheday(day)
	s += user
	h := sha1.New()
	h.Write([]byte(s))

	sha1hash := hex.EncodeToString(h.Sum(nil))

	// hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	return sha1hash
}

// Hashstring is just to hash the string
func Hashstring(str string) string {

	s := str
	h := sha1.New()
	h.Write([]byte(s))

	sha1hash := hex.EncodeToString(h.Sum(nil))

	return sha1hash
}

// GenerateToken generates a secure token of exactly 26 characters in length and returns it
func GenerateToken(userID string, ttl time.Duration) (Token, error) {

	emptytoken := Token{
		UserID: "",
		Expiry: time.Now(),
	}
	randomBytes := make([]byte, 245)
	// randomBytes := make([]byte, 16)

	_, err := rand.Read(randomBytes)
	if err != nil {
		return emptytoken, err
	}

	token := Token{
		UserID: userID,
		Expiry: time.Now().Add(ttl),
	}

	token.Token = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)
	hash := sha256.Sum256([]byte(token.Token))
	token.TokenHash = hash[:]

	return token, nil
}
