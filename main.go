// main.go
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
	"github.com/xdg-go/pbkdf2"
)

// EncryptionService handles encryption and decryption functionality.
type EncryptionService struct {
	client *mongo.Client
	store  *sessions.CookieStore
	logger *logrus.Logger
}

// NewEncryptionService creates a new EncryptionService.
func NewEncryptionService(client *mongo.Client, store *sessions.CookieStore, logger *logrus.Logger) *EncryptionService {
	return &EncryptionService{client: client, store: store, logger: logger}
}

func (s *EncryptionService) KeygenHandler(w http.ResponseWriter, r *http.Request) {
	aesKey := GenerateKey()
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		s.logger.Error("Failed to generate nonce: ", err)
		writeJSONResponse(w, http.StatusInternalServerError, "error", "Failed to generate nonce", nil)
		return
	}

	data := map[string]string{
		"key":   base64.StdEncoding.EncodeToString(aesKey),
		"nonce": base64.StdEncoding.EncodeToString(nonce),
	}
	writeJSONResponse(w, http.StatusOK, "success", "Key and nonce generated", data)
}

func (s *EncryptionService) EncryptHandler(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		s.logger.Error("Unable to upload file: ", err)
		writeJSONResponse(w, http.StatusBadRequest, "error", "Unable to upload file", nil)
		return
	}
	defer file.Close()

	plaintext, err := io.ReadAll(file)
	if err != nil {
		s.logger.Error("Unable to read file: ", err)
		writeJSONResponse(w, http.StatusInternalServerError, "error", "Unable to read file", nil)
		return
	}

	aesKeyBase64 := r.FormValue("aes_key")
	nonceBase64 := r.FormValue("nonce")
	aesKey, nonce, err := DecodeKeys(aesKeyBase64, nonceBase64)
	if err != nil {
		s.logger.Error("Key/Nonce decode error: ", err)
		writeJSONResponse(w, http.StatusBadRequest, "error", err.Error(), nil)
		return
	}

	encryptedFile, err := EncryptAESGCM(plaintext, aesKey, nonce)
	if err != nil {
		s.logger.Error("Encryption failed: ", err)
		writeJSONResponse(w, http.StatusInternalServerError, "error", "Unable to encrypt file", nil)
		return
	}

	encFileName := header.Filename + ".enc"
	w.Header().Set("Content-Disposition", "attachment; filename="+encFileName)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(encryptedFile)))

	_, err = w.Write(encryptedFile)
	if err != nil {
		s.logger.Error("Failed to write encrypted file to response: ", err)
		writeJSONResponse(w, http.StatusInternalServerError, "error", "Unable to write encrypted file to response", nil)
	}
}

func (s *EncryptionService) DecryptHandler(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		s.logger.Error("Unable to upload encrypted file: ", err)
		writeJSONResponse(w, http.StatusBadRequest, "error", "Unable to upload encrypted file", nil)
		return
	}
	defer file.Close()

	aesKeyBase64 := r.FormValue("aes_key")
	nonceBase64 := r.FormValue("nonce")
	aesKey, nonce, err := DecodeKeys(aesKeyBase64, nonceBase64)
	if err != nil {
		s.logger.Error("Key/Nonce decode error: ", err)
		writeJSONResponse(w, http.StatusBadRequest, "error", err.Error(), nil)
		return
	}

	encryptedFile, err := io.ReadAll(file)
	if err != nil {
		s.logger.Error("Unable to read encrypted file: ", err)
		writeJSONResponse(w, http.StatusInternalServerError, "error", "Unable to read encrypted file", nil)
		return
	}

	decryptedFile, err := DecryptAESGCM(encryptedFile, aesKey, nonce)
	if err != nil {
		s.logger.Error("Decryption failed: ", err)
		writeJSONResponse(w, http.StatusInternalServerError, "error", "Unable to decrypt file", nil)
		return
	}

	decryptedFileName := strings.TrimSuffix(header.Filename, ".enc")
	w.Header().Set("Content-Disposition", "attachment; filename="+decryptedFileName)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(decryptedFile)))

	_, err = w.Write(decryptedFile)
	if err != nil {
		s.logger.Error("Failed to write decrypted file to response: ", err)
		writeJSONResponse(w, http.StatusInternalServerError, "error", "Unable to write decrypted file to response", nil)
	}
}

// writeJSONResponse writes a JSON response to the client.
func writeJSONResponse(w http.ResponseWriter, statusCode int, status string, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  status,
		"message": message,
		"data":    data,
	})
}

// DecodeKeys decodes AES key and nonce from Base64.
func DecodeKeys(aesKeyBase64, nonceBase64 string) ([]byte, []byte, error) {
	aesKey, err := base64.StdEncoding.DecodeString(aesKeyBase64)
	if err != nil || len(aesKey) != 32 {
		return nil, nil, errors.New("invalid AES key format")
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceBase64)
	if err != nil || len(nonce) != 12 {
		return nil, nil, errors.New("invalid nonce format")
	}

	return aesKey, nonce, nil
}

// GenerateRandomPassword generates a random password of the given length.
func GenerateRandomPassword(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// DecryptAESGCM decrypts a ciphertext using AES-GCM.
func DecryptAESGCM(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

// GenerateKey generates a 256-bit AES key.
func GenerateKey() []byte {
	password, err := GenerateRandomPassword(16)
	if err != nil {
		log.Fatal(err)
	}

	salt := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		log.Fatal(err)
	}

	return pbkdf2.Key([]byte(password), salt, 10000, 32, sha256.New)
}

// EncryptAESGCM encrypts a plaintext using AES-GCM.
func EncryptAESGCM(plaintext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Seal(nil, nonce, plaintext, nil), nil
}

// main function
func main() {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Load configuration from environment variables
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}

	clientOptions := options.Client().ApplyURI(mongoURI)
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		logger.Fatal("Failed to connect to MongoDB: ", err)
	}
	defer client.Disconnect(context.Background())

	store := sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))
	service := NewEncryptionService(client, store, logger)

	r := mux.NewRouter()
	r.HandleFunc("/keygen", service.KeygenHandler).Methods(http.MethodGet)
	r.HandleFunc("/encrypt", service.EncryptHandler).Methods(http.MethodPost)
	r.HandleFunc("/decrypt", service.DecryptHandler).Methods(http.MethodPost)

	srv := &http.Server{
		Handler:      r,
		Addr:         ":8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	// Graceful shutdown
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed: ", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown: ", err)
	}

	logger.Info("Server exiting")
}
