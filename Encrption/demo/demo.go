package main

import (
	"fmt"


)


func main{
v := secret.File("my-fake-key", ".secrets")

plain, err := v.Get("demo_key1")
	if err != nil {
		panic(err)
	}
	fmt.Println("Plain:", plain)
	plain, err = v.Get("demo_key2")
	if err != nil {
		panic(err)
	}
	fmt.Println("Plain:", plain)
	plain, err = v.Get("demo_key3")
	if err != nil {
		panic(err)
	}
	fmt.Println("Plain:", plain)
}