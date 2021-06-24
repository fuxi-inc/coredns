package dnsserver

import (
        "log"
        "os"
        "strings"
)

func getCurrentDirectory() string {
        dir, err := os.Getwd()
        if err != nil {
                log.Fatal(err)
        }
        return strings.Replace(dir, "\\", "/", -1)
}
