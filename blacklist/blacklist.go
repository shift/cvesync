package blacklist

import (
	"bufio"
	"github.com/rs/zerolog/log"
	"github.com/shift/cvesync/nvd"
	"os"
	"strings"
)

type BlackList struct {
	items []string
}

func (b BlackList) Blacklisted(entry nvd.Entry) bool {
	result := false
	// Brute force approach
	for _, x := range entry.Products {
		for _, y := range b.items {
			if strings.Contains(x, y) {
				// BlackListed strings are substrings of Product lines
				result = true
			}
		}
	}
	return result
}

func Load_Blacklist(filename string) BlackList {
	blist := BlackList{}

	file, err := os.Open(filename)
	if err != nil {
		log.Error().Err(err).Msg("")
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Ignore empty lines
		if len(line) > 0 {
			blist.items = append(blist.items, scanner.Text())
		}
	}

	if err := scanner.Err(); err != nil {
		log.Error().Err(err).Msg("")
		panic(err)
	}

	return blist
}
