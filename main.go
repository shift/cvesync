package main

import (
	"database/sql"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/shift/cvesync/blacklist"
	"github.com/shift/cvesync/nvd"
	"github.com/shift/cvesync/tracker"
	"github.com/shift/cvesync/util"
)

var (
	config util.ServiceConfiguration
	blist  blacklist.BlackList
)

func sync(feed nvd.CVE, cwes nvd.CWE, ts tracker.Tracker) {
	db := util.Get_DB(config.DBFile)
	defer db.Close()

	// Initialize tracker
	ts.Init()

	// Reverse the order as the xml feed is sorted from newest to oldest
	for i := len(feed.Entries) - 1; i >= 0; i-- {
		entry := feed.Entries[i]
		// Is any of the mentioned products on the blacklist?
		if !blist.Blacklisted(entry) {
			sync_entry(entry, db, cwes, ts)
		} else {
			log.Warn().Str("entry_id", entry.Id).Msg("Not syncing %v because one of the products were blacklisted")
		}
	}
}

func sync_entry(entry nvd.Entry, db *sql.DB, cwes nvd.CWE, ts tracker.Tracker) {
	entry.CWE.CWECatalog = &cwes
	// Completely new?
	if !util.Exists(db, entry.Id) {
		log.Info().Str("entry_id", entry.Id).Msg("Adding new CVE")
		id, err := ts.Add(entry)
		if err != nil {
			log.Error().Err(err).Str("entry_id", entry.Id).Msg("Unable to add to issue tracker")
			return
		}
		// Add to database, too
		util.DB_Add(db, entry.Id, entry.Last_Modified, id)
		// Already existing, but modified?
	} else if !util.Modified_Matches(db, entry.Id, entry.Last_Modified) {
		log.Info().Str("entry_id", entry.Id).Msg("Modifying old CVE")
		ticketid := util.DB_TicketID(db, entry.Id)
		err := ts.Update(entry, ticketid)
		if err != nil {
			log.Error().Err(err).Str("entry_id", entry.Id).Msg("Unable to modify in issue tracker")
			return
		}
		// Update to database, too
		util.DB_Update(db, entry.Id, entry.Last_Modified)
	}
}

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	zerolog.TimeFieldFormat = ""
	log.Info().Msg("Cvesync started")

	config = util.Load_Config("/opt/cvesync/etc/settings.json")
	blist = blacklist.Load_Blacklist(config.BlackList)
	cve_feed := nvd.Get_CVE_feed(config.FeedURL, config.CAKeyFile)
	cwes := nvd.Get_CWEs(config.CWEfile)

	ts := tracker.Jira{}
	sync(cve_feed, cwes, &ts)

	log.Info().Msg("Cvesync ended")
}
