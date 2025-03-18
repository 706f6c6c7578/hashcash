package hashcash

import (
    "crypto/rand"
    "crypto/sha1"
    "encoding/base64"
    "fmt"
    "hash"
    "math"
    "strconv"
    "strings"
    "time"
)

// Hash provides an implementation of hashcash v1.
type Hash struct {
    hasher  hash.Hash // SHA-1
    bits    uint      // Number of zero bits
    zeros   uint      // Number of zero digits
    saltLen uint      // Random salt length
    extra   string    // Extension to add to the minted stamp
}

// New creates a new Hash with specified options.
func New(bits uint, saltLen uint, extra string) *Hash {
    h := &Hash{
        hasher:  sha1.New(),
        bits:    bits,
        saltLen: saltLen,
        extra:   extra}
    h.zeros = uint(math.Ceil(float64(h.bits) / 4.0))
    return h
}

// Mint a new hashcash stamp for resource.
func (h *Hash) Mint(resource string) (string, error) {
    salt, err := h.getSalt()
    if err != nil {
        return "", err
    }
    date := time.Now().Format(dateFormat)
    counter := 0
    var stamp string
    for {
        stamp = fmt.Sprintf("1:%d:%s:%s:%s:%s:%x",
            h.bits, date, resource, h.extra, salt, counter)
        if h.checkZeros(stamp) {
            return stamp, nil
        }
        counter++
    }
}

// Check whether a hashcash stamp is valid.
func (h *Hash) Check(stamp string) bool {
    // Split the stamp into its components
    fields := strings.Split(stamp, ":")
    if len(fields) != 7 {
        return false
    }

    // Parse the bits field from the stamp
    stampBits, err := strconv.ParseUint(fields[1], 10, 32)
    if err != nil || uint(stampBits) < h.bits {
        // If parsing fails or the stamp's bits are lower than required, it's invalid
        return false
    }

    // Check the date
    if !h.checkDate(stamp) {
        return false
    }

    // Check the leading zero bits
    return h.checkZeros(stamp)
}

func (h *Hash) getSalt() (string, error) {
    buf := make([]byte, h.saltLen)
    _, err := rand.Read(buf)
    if err != nil {
        return "", err
    }
    salt := base64.StdEncoding.EncodeToString(buf)
    return salt[:h.saltLen], nil
}

// checkZeros counts the leading zero bits in the hash of the stamp.
func (h *Hash) checkZeros(stamp string) bool {
    h.hasher.Reset()
    h.hasher.Write([]byte(stamp))
    sum := h.hasher.Sum(nil)

    // Count the number of leading zero bits
    var zeroBits uint
    for _, b := range sum {
        if b == 0 {
            zeroBits += 8
        } else {
            // Count leading zeros in the current byte
            for mask := byte(0x80); mask > 0; mask >>= 1 {
                if b&mask == 0 {
                    zeroBits++
                } else {
                    break
                }
            }
            break
        }
    }

    // Ensure the number of leading zero bits matches the required bits
    return zeroBits >= h.bits
}

// checkDate validates the date field of the stamp.
func (h *Hash) checkDate(stamp string) bool {
    fields := strings.Split(stamp, ":")
    if len(fields) != 7 {
        return false
    }
    then, err := time.Parse(dateFormat, fields[2])
    if err != nil {
        return false
    }
    duration := time.Since(then)
    return duration.Hours()*2 <= 48
}

const dateFormat = "060102"