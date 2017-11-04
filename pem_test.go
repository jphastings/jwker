package main

import (
  "testing"
  "io/ioutil"
)

func TestPemToJwkEC(t *testing.T) {
  pemBytes, _ := ioutil.ReadFile("test_data/ec.pem")
  jwkBytes, _ := ioutil.ReadFile("test_data/ec.jwk")

  result := PemToJwk(pemBytes)

  if result != string(jwkBytes) {
    t.Error("output EC jwk does not match fixture:", result)
  }
}

func TestPemToJwkRSA(t *testing.T) {
  pemBytes, _ := ioutil.ReadFile("test_data/rsa.pem")
  jwkBytes, _ := ioutil.ReadFile("test_data/rsa.jwk")

  result := PemToJwk(pemBytes)

  if result != string(jwkBytes) {
    t.Error("output RSA jwk does not match fixture:", result)
  }
}
