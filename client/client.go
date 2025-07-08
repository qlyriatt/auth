package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
)

const url = "http://localhost:8080"

var (
	access_token  string
	refresh_token string
	guid          uuid.UUID
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	guid = uuid.New()
	fmt.Println("current id: ", guid)

	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		input := scanner.Text()
		inputs := strings.Split(strings.TrimSpace(input), " ")
		if len(inputs) == 0 {
			continue
		}

		switch inputs[0] {
		case "regen":
			guid = uuid.New()
			fmt.Println("new id: ", guid)
		case "auth":
			auth()
		case "refresh":
			refresh()
		case "id":
			getID()
		case "unauth":
			unauth()
		case "help":
			fmt.Println("Usage:")
			fmt.Println("  list")
			fmt.Println("  regen")
			fmt.Println("  auth")
			fmt.Println("  refresh")
			fmt.Println("  id")
			fmt.Println("  unauth")
		default:
			fmt.Println("Unknown command")
		}
	}
}

func auth() {
	body, _ := json.Marshal(map[string]string{"id": guid.String()})

	resp, err := http.Post(url+"/auth", "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bytes, _ := io.ReadAll(resp.Body)
		fmt.Println(string(bytes))
		return
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)

	access_token = result["access_token"]
	refresh_token = result["refresh_token"]
	fmt.Println("Access Token:", access_token)
	fmt.Println("Refresh Token:", refresh_token)
}

func refresh() {
	body, _ := json.Marshal(map[string]string{"refresh_token": refresh_token})

	req, err := http.NewRequest("POST", url+"/refresh", bytes.NewBuffer(body))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+access_token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bytes, _ := io.ReadAll(resp.Body)
		fmt.Println(string(bytes))
		return
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)

	access_token = result["access_token"]
	refresh_token = result["refresh_token"]
	fmt.Println("New access Token:", access_token)
	fmt.Println("New refresh Token:", refresh_token)
}

func getID() {
	req, err := http.NewRequest("GET", url+"/id", nil)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+access_token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bytes, _ := io.ReadAll(resp.Body)
		fmt.Println(string(bytes))
		return
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	fmt.Println("Returned ID: ", result["id"])
}

func unauth() {
	req, err := http.NewRequest("POST", url+"/unauth", nil)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+access_token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bytes, _ := io.ReadAll(resp.Body)
		fmt.Println(string(bytes))
		return
	}
}
