package nvd

import (
	"encoding/xml"
	"github.com/rs/zerolog/log"
	"io/ioutil"
)

type CWE struct {
	Weaknesses []Weakness `xml:"Weaknesses>Weakness"`
}

type Weakness struct {
	ID          string `xml:"ID,attr"`
	Description string `xml:"Description>Description_Summary"`
}

func Unmarshal_CWE(data []byte) CWE {
	var c CWE
	err := xml.Unmarshal(data, &c)
	if err != nil {
		log.Error().Err(err).Msg("")
		panic(err)
	}

	return c
}

func Get_CWEs(filename string) CWE {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Error().Err(err).Msg("Unable to read CWE file")
		panic(err)
	}

	cwes := Unmarshal_CWE(b)
	return cwes
}
